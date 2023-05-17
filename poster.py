"""
    usage: poster.py [-h] [-r RELAY] [-a AS_USER] [-t TO_USERS] [-v VIA] [-s SUBJECT] [-p]
                 [-i] [-l] [-d]
                 [message ...]

post nostr text(1) and encrypted text(4) events from the command line

positional arguments:
  message               an integer for the accumulator

options:
  -h, --help            show this help message and exit
  -r RELAY, --relay RELAY
                        comma separated nostr relays to connect to,
                        default[ws://localhost:8081]
  -a AS_USER, --as_user AS_USER
                        alias, priv_k of user to post as, default[monty]
  -t TO_USERS, --to_users TO_USERS
                        comma seperated alias, priv_k, or pub_k of user to post to,
                        default[None]
  -v VIA, --via VIA     alias(with priv_k) or nsec that will be used as public inbox
                        with wrapped events, default[None]
  -s SUBJECT, --subject SUBJECT
                        add subject tag to post,, default[None]
  -p, --plain_text      post as plain text
  -i, --ignore_missing  don't fail on missing to_users
  -l, --loop            stay open to enter and receive messages
  -d, --debug           enable debug output

"""
import logging
import asyncio
from pathlib import Path
import argparse
from monstr.ident.profile import Profile
from monstr.ident.event_handlers import NetworkedProfileEventHandler
from monstr.ident.alias import ProfileFileAlias
from monstr.client.client import ClientPool, Client
from monstr.event.event import Event
from app.post import PostApp
from cmd_line.post_loop_app import PostAppGui
from monstr.encrypt import Keys
from monstr.util import util_funcs
from util import ConfigError, load_toml

# defaults if not otherwise given
# working directory it'll be created it it doesn't exist
WORK_DIR = f'{Path.home()}/.nostrpy/'
# relay/s to attach to
RELAYS = 'ws://localhost:8081'
# lookup profiles here
ALIAS_FILE = f'{WORK_DIR}profiles.csv'
# config from toml file
CONFIG_FILE = f'{WORK_DIR}poster.toml'


def show_post_info(as_user: Profile,
                   msg: str,
                   to_users: [Profile],
                   is_encrypt: bool,
                   subject: str,
                   public_inbox: Profile):
    if msg is None:
        msg = '<no msg supplied>'
    just = 10
    print('from:'.rjust(just), as_user.display_name())
    if to_users:
        p: Profile
        print('to:'.rjust(just), [p.display_name() for p in to_users])
    if public_inbox:
        print('via:'.rjust(just), public_inbox.display_name())

    if subject:
        print('subject:'.rjust(just), subject)

    enc_text = 'encrypted'
    if not is_encrypt:
        enc_text = 'plain_text'
    print('format:'.rjust(just), enc_text)

    print('%s\n%s\n%s' % (''.join(['-'] * 10),
                          msg,
                          ''.join(['-'] * 10)))


def create_key(key_val: str, for_desc: str, alias_map: ProfileFileAlias = None) -> Keys:
    try:
        ret = Keys.get_key(key_val)
        if ret is None and alias_map:
            p = alias_map.get_profile(key_val)
            if p:
                ret = p.keys

        if ret is None:
            raise Exception()

    except Exception as e:
        raise ConfigError(f'unable to create {for_desc} keys using - {key_val}')

    if ret.private_key_hex() is None:
        raise ConfigError(f'unable to create {for_desc} private keys using - {key_val}')
    return ret


def get_user_keys(user: str, alias_map: ProfileFileAlias = None) -> Keys:

    if user is None:
        raise ConfigError('no user supplied')
    elif user == '?':
        ret = Keys()
        print('created adhoc key - %s/%s' % (ret.public_key_hex(),
                                             ret.public_key_bech32()))
    else:
        ret = create_key(user, 'user', alias_map)

    return ret


def get_to_keys(to_users: [str], ignore_missing: bool, alias_map: ProfileFileAlias = None) -> [Keys]:
    ret = []
    if to_users is not None:
        for c_to in to_users:
            try:
                cu_key = Keys.get_key(c_to)
                if cu_key is None and alias_map:
                    p = alias_map.get_profile(c_to)
                    if p:
                        cu_key = p.keys

                if cu_key is None:
                    raise Exception()
                ret.append(cu_key)
            except Exception as e:
                if ignore_missing:
                    logging.info('unable to create keys for to_user using - %s - ignoring' % c_to)
                else:
                    raise ConfigError('unable to create keys for to_user using - %s' % c_to)

        if not ret:
            raise ConfigError('unable to create any to user keys!')

    return ret


def create_post_event(user: Keys,
                      is_encrypt: bool,
                      subject: str,
                      to_users: [Keys],
                      inbox: str,
                      message: str):

    kind = Event.KIND_ENCRYPT
    if not is_encrypt:
        kind = Event.KIND_TEXT_NOTE

    ret = Event(kind=kind,
                pub_key=user.public_key_hex(),
                content=message)

    if is_encrypt:
        ret.content = ret.encrypt_content(priv_key=user.private_key_hex(),
                                          pub_key=to_users[0].public_key_hex())

    evt_tags = []
    if subject:
        evt_tags.append(['subject', subject])
    if to_users:
        evt_tags = evt_tags + [['p', k.public_key_hex()] for k in to_users]

    ret.tags = evt_tags

    if inbox:
        pass

    return ret


async def get_poster(client: Client,
                     user_k: Keys,
                     to_users_k: Keys,
                     inbox_k: Keys,
                     is_encrypt: bool,
                     subject: str):
    k: Keys

    # get profiles of from/to if we can
    peh = NetworkedProfileEventHandler(client=client)

    # make list of p keys we need
    p_to_fetch = [user_k.public_key_hex()]
    if to_users_k:
        p_to_fetch = p_to_fetch + [k.public_key_hex() for k in to_users_k]
    if inbox_k:
        p_to_fetch = p_to_fetch + [inbox_k.public_key_hex()]

    # pre-fetch them, creating stubs for any we didn't find
    await peh.get_profiles(pub_ks=p_to_fetch, create_missing=True)

    # get the sending user profile
    user_p = await peh.get_profile(pub_k=user_k.public_key_hex())
    # because relay doesn't know the private key
    user_p.private_key = user_k.private_key_hex()

    # and for the inbox, normally we wouldn't expect this to have a profile
    inbox_p = None
    if inbox_k:
        inbox_p = await peh.get_profile(inbox_k.public_key_hex())
        # again the relay wouldn't know this
        inbox_p.private_key = inbox_k.private_key_hex()

    # get the to users profile if any
    to_users_p = None
    if to_users_k:
        to_users_p = await peh.get_profiles([k.public_key_hex() for k in to_users_k])

    post_app = PostApp(use_relay=client,
                       as_user=user_p,
                       to_users=to_users_p,
                       public_inbox=inbox_p,
                       subject=subject,
                       is_encrypt=is_encrypt)
    return {
        'post_app': post_app,
        'user': user_p,
        'to_users': to_users_p,
        'inboxes': inbox_p
    }


async def post_single(relays: [str],
                      user_k: Keys,
                      to_users_k: Keys,
                      inbox_k: Keys,
                      is_encrypt: bool,
                      subject: str,
                      message: str):

    async with ClientPool(relays, timeout=10) as client:
        post_env = await get_poster(client=client,
                                    user_k=user_k,
                                    to_users_k=to_users_k,
                                    inbox_k=inbox_k,
                                    is_encrypt=is_encrypt,
                                    subject=subject)

        post_app: PostApp = post_env['post_app']
        user: Profile = post_env['user']
        to_users: [Profile] = post_env['to_users']
        inboxes: [Profile] = post_env['inboxes']

        show_post_info(as_user=user,
                       to_users=to_users,
                       is_encrypt=is_encrypt,
                       subject=subject,
                       public_inbox=inboxes,
                       msg=message)

        post_app.do_post(msg=message)
        # hack to give time for the event to be sent
        await asyncio.sleep(1)


async def post_loop(relays: [str],
                    user_k: Keys,
                    to_users_k: Keys,
                    inbox_k: Keys,
                    is_encrypt: bool,
                    subject: str):

    sub_id: str = None
    con_status = None

    kinds = Event.KIND_ENCRYPT
    # if we're using an inbox then events are always encrypted type 4
    # though they may be unencrypted to anyone who has the inbox keys
    if is_encrypt is False and not inbox_k:
        kinds = Event.KIND_TEXT_NOTE

    def do_sub():
        nonlocal sub_id

        filter = {
            'kinds': [kinds],
            'limit': 10
        }
        if inbox_k:
            filter['authors'] = inbox_k.public_key_hex()

        # can only be applied on non wrapped, otherwise needs to be filtered by post app
        if subject and inbox_k is None:
            filter['#subject'] = subject

        sub_id = my_client.subscribe(handlers=[post_app],
                                     filters=filter,
                                     sub_id=sub_id)

    def on_status(status):
        nonlocal con_status
        if con_status != status['connected']:
            con_status = status['connected']
            asyncio.create_task(my_gui.draw_messages())

    def on_eose(the_client: Client, sub_id:str, evts: [Event]):
        Event.sort(evts=evts,
                   inplace=True,
                   reverse=False)
        c_evt: Event
        u_authors = list({c_evt.pub_key for c_evt in evts})
        # batch get authors otherwise requests would be fire 1 by 1 as needed
        # and the relay is likely to error us on number of subs
        async def do_events():
            await peh.get_profiles(u_authors,
                             create_missing=True)
            for c_evt in evts:
                post_app.do_event(the_client, sub_id, c_evt)

        asyncio.create_task(do_events())

    def on_connect(the_client: Client):
        do_sub()

    async with ClientPool(relays) as my_client:
        peh = NetworkedProfileEventHandler(client=my_client)
        post_env = await get_poster(client=my_client,
                                    user_k=user_k,
                                    to_users_k=to_users_k,
                                    inbox_k=inbox_k,
                                    is_encrypt=is_encrypt,
                                    subject=subject)

        post_app: PostApp = post_env['post_app']
        my_gui = PostAppGui(post_app,
                            profile_handler=peh)

        my_client.set_on_status(on_status)
        my_client.set_on_eose(on_eose)
        my_client.set_on_connect(on_connect)

        # manually call the connect which just adds the sub
        on_connect(my_client)
        await my_gui.run()


def get_cmdline_args(args) -> dict:
    parser = argparse.ArgumentParser(
        prog='poster.py',
        description="""
            post nostr text(1) and encrypted text(4) events from the command line
            """
    )
    parser.add_argument('-r', '--relay', action='store', default=args['relay'],
                        help=f'comma separated nostr relays to connect to, default[{args["relay"]}]')
    parser.add_argument('-a', '--as_user', action='store', default=args['as_user'],
                        help=f"""
                        alias, priv_k of user to post as,
                        default[{args['as_user']}]""")
    parser.add_argument('-t', '--to_users', action='store', default=args['to_users'],
                        help=f"""
                        comma seperated alias, priv_k, or pub_k of user to post to,
                        default[{args['to_users']}]""")
    parser.add_argument('-v', '--via', action='store', default=args['via'],
                        help=f"""
                            alias(with priv_k) or nsec that will be used as public inbox with wrapped events,
                            default[{args['via']}]""")
    parser.add_argument('-s', '--subject', action='store', default=args['subject'],
                        help=f"""
                                add subject tag to post,,
                                default[{args['subject']}]""")

    parser.add_argument('message', type=str, nargs='*',
                       help='an integer for the accumulator')
    parser.add_argument('-p', '--plain_text', action='store_false', help='post as plain text',
                        dest='encrypt')

    parser.add_argument('-i', '--ignore_missing', action='store_true', help='don\'t fail on missing to_users')
    parser.add_argument('-l', '--loop', action='store_true', help='stay open to enter and receive messages')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')

    ret = parser.parse_args()

    return vars(ret)


def get_args() -> dict:
    """
    get args to use order is
        default -> toml_file -> cmd_line options

    so command line option is given priority if given

    :return: {}
    """

    ret = {
        'relay': RELAYS,
        'as_user': None,
        'to_users': None,
        'via': None,
        'encrypt': True,
        'ignore_missing': False,
        'subject': None,
        'message': None,
        'loop': False,
        'alias_file': ALIAS_FILE,
        'debug': False
    }

    # now form config file if any
    ret.update(load_toml(CONFIG_FILE))

    # now from cmd line
    ret.update(get_cmdline_args(ret))

    # if debug flagged enable now
    if ret['debug'] is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(f'get_args:: running with options - {ret}')

    return ret


async def main(args):
    # post to these relays
    relays = args['relay'].split(',')

    # we'll post as this user
    user = args['as_user']

    # post to these users
    to_users = args['to_users']
    if to_users:
        to_users = to_users.split(',')

    # msgs wrapped via this in box (priv key that we know and so should those we post to)
    inbox = args['via']

    # don't fail just because we can't find all to_users
    ignore_missing = args['ignore_missing']

    # open gui so we can type mutiple messages, in this case message text isn't required
    loop = args['loop']

    # message text to be sent if not loop mode
    message = ' '.join(args['message'])

    # subject text for message/ each message
    subject = args['subject']

    # encryped kind 4 events
    is_encrypt = args['encrypt']

    # file used to lookup aliases
    alias_file = args['alias_file']

    # human alias to keys
    key_alias = ProfileFileAlias(alias_file)

    try:
        if loop is False and not message:
            raise ConfigError('no message supplied to post')

        user_keys = get_user_keys(user,
                                  alias_map=key_alias)

        if is_encrypt and to_users is None:
            raise ConfigError('to users is required for encrypted messages')

        to_keys = get_to_keys(to_users, ignore_missing,
                              alias_map=key_alias)

        inbox_keys = None
        if inbox:
            inbox_keys = get_user_keys(inbox, alias_map=key_alias)

        if loop is False:
            await post_single(relays=relays,
                              user_k=user_keys,
                              to_users_k=to_keys,
                              inbox_k=inbox_keys,
                              is_encrypt=is_encrypt,
                              subject=subject,
                              message=message
                              )
        else:
            await post_loop(relays=relays,
                            user_k=user_keys,
                            to_users_k=to_keys,
                            inbox_k=inbox_keys,
                            is_encrypt=is_encrypt,
                            subject=subject
                            )

    except ConfigError as ce:
        print(ce)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.FATAL)
    util_funcs.create_work_dir(WORK_DIR)
    asyncio.run(main(get_args()))
    # print(get_args())



