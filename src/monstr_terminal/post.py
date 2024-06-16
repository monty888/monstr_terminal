import logging
import asyncio
from pathlib import Path
import argparse
from monstr.ident.profile import Profile
from monstr.ident.event_handlers import NetworkedProfileEventHandler
from monstr.client.client import ClientPool, Client
from monstr.event.event import Event
from monstr_terminal.app.post import PostApp
from monstr.inbox import Inbox
from monstr_terminal.cmd_line.post_loop_app import PostAppGui
from monstr.encrypt import Keys, DecryptionException
from monstr.signing.signing import BasicKeySigner, SignerInterface
from monstr.util import util_funcs, ConfigError
from monstr_terminal.util import load_toml, get_sqlite_key_store, get_signer_from_str
from monstr.ident.keystore import KeystoreInterface
"""
    TODO: add support for NIP44 encryption 
"""

# defaults if not otherwise given
# working directory it'll be created it it doesn't exist
WORK_DIR = f'{Path.home()}/.nostrpy/'
# filename for key store
KEY_STORE_DB_FILE = 'keystore.db'
# relay/s to attach to
RELAYS = 'ws://localhost:8081'
# user to post as
USER = None
# config from toml file
CONFIG_FILE = 'poster.toml'
# default kind for inbox wrap events
INBOX_KIND = Event.KIND_ENCRYPT


# async def create_key(key_val: str, for_desc: str, key_store: KeystoreInterface = None) -> Keys:
#     ret = Keys.get_key(key_val)
#     if ret is None and key_store:
#         ret = await key_store.get(key_val)
#
#     if ret is None:
#         raise ConfigError(f'unable to create {for_desc} keys using - {key_val}')
#
#     if ret.private_key_hex() is None:
#         raise ConfigError(f'unable to create {for_desc} private keys using - {key_val}')
#     return ret


async def get_user_signer(user: str,
                          key_store: KeystoreInterface = None) -> SignerInterface:

    # special ?, we'll just create some random keys to post as
    if user == '?':
        adhoc_k = Keys()
        ret = BasicKeySigner(adhoc_k)
        print(f'created adhoc key for {for_desc} - {adhoc_k.private_key_bech32()}')
    else:
        ret = await get_signer_from_str(key=user, key_store=key_store)

    return ret


async def get_to_keys(to_users: [str], ignore_missing: bool, key_store: KeystoreInterface = None) -> [Keys]:
    ret = []
    if to_users is not None:
        for c_to in to_users:
            # get rid of anyspaces
            # TODO: keystore needs to enforce non space in key names
            c_to = c_to.replace(' ', '')

            cu_key = Keys.get_key(c_to)
            if cu_key is None and key_store:
                cu_key = await key_store.get(c_to)

            if cu_key is None:
                # just note
                if ignore_missing:
                    logging.info(f'unable to create keys for to_user using - {c_to} - ignoring')
                # bug out
                else:
                    raise ConfigError(f'unable to create keys for to_user using - {c_to}')
            else:
                ret.append(cu_key)

        # even with ignore_missing we need atleast 1 to user
        if not ret:
            raise ConfigError('unable to create any to user keys!')

    return ret


async def get_poster(client: Client,
                     profile_handler: NetworkedProfileEventHandler,
                     user_sign: SignerInterface,
                     to_users_k: [Keys],
                     inbox_sign: SignerInterface,
                     inbox_kind: int,
                     is_encrypt: bool,
                     subject: str,
                     kind: int,
                     tags: str) -> PostApp:
    k: Keys

    # are we going via an inbox?
    inbox = None
    if inbox_sign:
        inbox = await get_inbox(inbox_sign=inbox_sign,
                                user_sign=user_sign,
                                to_keys=to_users_k,
                                inbox_kind=inbox_kind,
                                profile_handler=profile_handler)

    post_app = PostApp(use_relay=client,
                       profile_handler=profile_handler,
                       user_sign=user_sign,
                       to_users_k=to_users_k,
                       inbox=inbox,
                       subject=subject,
                       is_encrypt=is_encrypt,
                       kind=kind,
                       tags=tags)

    await post_app.wait_ready()

    return post_app


async def get_inbox(inbox_sign: SignerInterface,
                    user_sign: SignerInterface,
                    to_keys: [Keys],
                    inbox_kind: int,
                    profile_handler: NetworkedProfileEventHandler=None) -> Inbox:
    # are we going via an inbox?
    ret = None
    inbox_pub_k = await inbox_sign.get_public_key()

    # if given a profile handler we'll attempt to get a name for the inbox (from meta event)
    if profile_handler is not None:
        inbox_p: Profile = await profile_handler.aget_profile(inbox_pub_k, create_missing=True)
        name = inbox_p.display_name()

    # actually create the inbox
    ret = Inbox(signer=inbox_sign,
                name=name,
                use_kind=inbox_kind)

    # generate share map for any encrypts over the inbox
    if to_keys:
        await ret.set_share_map(for_sign=user_sign,
                                to_keys=to_keys)

    return ret


async def post_single(relays: [str],
                      user_sign: SignerInterface,
                      to_users_k: Keys,
                      inbox_sign: SignerInterface,
                      inbox_kind: int,
                      is_encrypt: bool,
                      subject: str,
                      message: str,
                      kind: int = None,
                      tags: str = None):

    def on_auth(the_client: Client, challenge: str):
        auth_sign = user_sign
        if inbox_sign:
            auth_sign = inbox_sign

        asyncio.create_task(the_client.auth(auth_sign, challenge))

    async with ClientPool(relays, timeout=10, on_auth=on_auth) as client:
        try:
            post_app = await get_poster(client=client,
                                        profile_handler=NetworkedProfileEventHandler(client=client),
                                        user_sign=user_sign,
                                        to_users_k=to_users_k,
                                        inbox_sign=inbox_sign,
                                        inbox_kind=inbox_kind,
                                        is_encrypt=is_encrypt,
                                        subject=subject,
                                        kind=kind,
                                        tags=tags)

            await post_app.show_post_info(message)
            await post_app.do_post(message)
        except Exception as e:
            print(e)



        # hack to give time for the event to be sent
        await asyncio.sleep(1)


async def post_loop(relays: [str],
                    user_sign: SignerInterface,
                    to_users_k: [Keys],
                    inbox_sign: SignerInterface,
                    inbox_kind: int,
                    is_encrypt: bool,
                    subject: str,
                    kind: int,
                    tags: str):

    sub_id: str = None
    con_status = None

    inbox_pub_k = None
    if inbox_sign:
        inbox_pub_k = await inbox_sign.get_public_key()

    # if we're using an inbox then events are always encrypted type 4
    # though they may be unencrypted to anyone who has the inbox keys
    def do_sub():
        nonlocal sub_id

        filter = {
            'kinds': [kind],
            'limit': 10
        }
        if inbox_pub_k:
            filter['authors'] = [inbox_pub_k]
            filter['kinds'] = [inbox_kind]

        # can only be applied on non wrapped, otherwise needs to be filtered by post app
        if subject and inbox_pub_k is None:
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
            await peh.aget_profiles(u_authors,
                                    create_missing=True)
            for c_evt in evts:
                post_app.do_event(the_client, sub_id, c_evt)

        asyncio.create_task(do_events())

    def on_connect(the_client: Client):
        do_sub()

    def on_auth(the_client: Client, challenge: str):
        auth_sign = user_sign
        if inbox_sign:
            auth_sign = inbox_sign

        asyncio.create_task(the_client.auth(auth_sign, challenge))


    # EOSE based fetch of historic events doesn't work very well with multiple clients
    # TODO: change to initial query then sub based?
    async with ClientPool(relays,
                          on_auth=on_auth,
                          on_eose=on_eose) as my_client:
        peh = NetworkedProfileEventHandler(client=my_client)
        post_app = await get_poster(client=my_client,
                                    profile_handler=peh,
                                    user_sign=user_sign,
                                    to_users_k=to_users_k,
                                    inbox_sign=inbox_sign,
                                    inbox_kind=inbox_kind,
                                    is_encrypt=is_encrypt,
                                    subject=subject,
                                    kind=kind,
                                    tags=tags)

        my_gui = PostAppGui(post_app,
                            profile_handler=peh,
                            is_encrypt=is_encrypt)

        my_client.set_on_status(on_status)
        # my_client.set_on_eose(on_eose)
        my_client.set_on_connect(on_connect)

        # manually call the connect which just adds the sub
        on_connect(my_client)
        await my_gui.run()


def get_cmdline_args(args) -> dict:
    parser = argparse.ArgumentParser(
        prog='post.py',
        description="""
            post nostr events from the command line
            """
    )
    parser.add_argument('-r', '--relay', action='store', default=args['relay'],
                        help=f'comma separated nostr relays to connect to, default [{args["relay"]}]')
    parser.add_argument('-u', '--user', action='store', default=args['user'],
                        help=f"""
                        alias, priv_k of user to post as,
                        default [{args['user']}]""")
    parser.add_argument('-t', '--to_users', action='store', default=args['to_users'],
                        help=f"""
                        comma seperated alias, priv_k, or pub_k of user to post to,
                        default [{args['to_users']}]""")
    parser.add_argument('-v', '--via', action='store', default=args['via'],
                        help=f"""
                            alias(with priv_k) or nsec that will be used as public inbox with wrapped events,
                            default [{args['via']}]""")
    parser.add_argument('-s', '--subject', action='store', default=args['subject'],
                        help=f"""
                                add subject tag to post,,
                                default[{args['subject']}]""")
    parser.add_argument('--tags', action='store', default=args['tags'],
                        help=f"""
                                tags to add post in format tagname:v1,v2#tagname:v1...
                                default [{args["tags"]}]
    """)
    parser.add_argument('message', type=str, nargs='*',
                       help='message to post')
    parser.add_argument('-k', '--kind', action='store', help="""
                                kind of event to post, if not given used kind depends on format -
                                if default or plaintext then [1] if encrypt then [4]"""
                        , type=int,
                        dest='kind')
    parser.add_argument('--inbox-kind', action='store',
                        help=f'if using an inbox, what kind is used for the wrapping event default [{args["inbox_kind"]}]',
                        type=int,default=int(args["inbox_kind"]),
                        dest='inbox_kind')

    parser.add_argument('-f', '--format', action='store', help="""
    format of the event content if default is selected then events of kind 4 will be encrypted and all other kinds will 
    be plaintext
    """, choices={
        'plaintext',
        'encrypt',
        'default'
    }, default='default')

    parser.add_argument('-i', '--ignore_missing', action='store_true', help='don\'t fail on missing to_users')
    parser.add_argument('-l', '--loop', action='store_true', help='stay open to enter and receive messages')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')

    ret = parser.parse_args()

    return vars(ret)


def get_tags(tags: str) -> [[]]:
    ret = None
    for c_tag in tags.split('#'):
        split_vals = c_tag.split(':')
        if len(split_vals) < 2:
            logging.debug(f'get_tags: ignoring {split_vals} no values')
        else:
            if ret is None:
                ret = []
            ret.append(split_vals)

    logging.debug(f'get_tags: got tag values {ret}')
    return ret


def get_args() -> dict:
    """
    get args to use order is
        default -> toml_file -> cmd_line options

    so command line option is given priority if given

    :return: {}
    """

    ret = {
        'relay': RELAYS,
        'work_dir': WORK_DIR,
        'conf': CONFIG_FILE,
        'user': USER,
        'to_users': None,
        'via': None,
        'format': 'default',
        'kind': None,
        'inbox_kind': INBOX_KIND,
        'ignore_missing': False,
        'subject': None,
        'tags': None,
        'message': None,
        'loop': False,
        'alias_file': KEY_STORE_DB_FILE,
        'keystore': {
            'filename': WORK_DIR + KEY_STORE_DB_FILE,
            'password': None
        },
        'debug': False
    }

    # now form config file if any
    load_toml(filename=ret['conf'],
              dir=ret['work_dir'],
              current_args=ret)

    # now from cmd line
    ret.update(get_cmdline_args(ret))

    # if any tags, see if we can make into anything sensible...
    if ret['tags']:
        ret['tags'] = get_tags(ret['tags'])

    # if not given get a user
    if ret['user'] is None:
        ret['user'] = input('as user: ')

    # work out if we're making encrypted posts
    format = ret['format']
    kind = ret['kind']
    is_encrypt = format == 'encrypt'

    # no kind given, so now we'll choose one, maybe overwrite is_encrypt
    if kind is None:
        if format in {'encrypt', 'default'}:
            kind = 4
            is_encrypt = True
        else:
            kind = 1
    # kind has been given, for format default we'll now override is_encrypt
    else:
        # default which is encrypt only for kind 4
        if format == 'default':
            is_encrypt = kind == 4

    ret['is_encrypt'] = is_encrypt
    ret['kind'] = kind

    # to users are required for encypted msgs, so ask for to users!
    if is_encrypt and ret['to_users'] is None:
        ret['to_users'] = input('to users: ')

    # if we msg we reduce any spacing, maybe we shouldn't bother?
    if ret['message']:
        ret['message'] = ' '.join(ret['message'])

    # msg isn't required in loop mode - in fact it's ignored.. maybe we should still send it if given?
    # anyway if not loop we will need a msg
    elif ret['loop'] is False and not ret['message']:
        ret['message'] = input('message: ')


    # if debug flagged enable now and output args we're running with
    if ret['debug'] is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(f'get_args:: running with options - {ret}')

    return ret


async def main(args):
    # post to these relays
    relays = args['relay'].split(',')

    # we'll post as this user
    user = args['user']

    # post to these users
    to_users = args['to_users']
    if to_users:
        to_users = to_users.split(',')

    # msgs wrapped via this in box (priv key that we know and so should those we post to)
    inbox = args['via']
    inbox_kind = args['inbox_kind']

    # don't fail just because we can't find all to_users
    ignore_missing = args['ignore_missing']

    # open gui so we can type mutiple messages, in this case message text isn't required
    loop = args['loop']

    # message text to be sent if not loop mode
    message = args['message']

    # subject text for message/ each message
    subject = args['subject']

    # args we encrypting? (NIP4 at the moment)
    is_encrypt = args['is_encrypt']
    # kind of event to post by default this will be 1 for plaintxt or 4 for encrypt
    kind = args['kind']

    # tags if any to be added to posts
    tags = args['tags']

    # keystore for user key aliases
    key_store = get_sqlite_key_store(db_file=WORK_DIR+args['alias_file'],
                                     password=args['keystore']['password'])

    # user to sign are post events, eventually this might be NIP46 client
    # (we don't have the keys locally)
    user_signer = await get_user_signer(user=user,
                                        key_store=key_store)

    # to keys, opt for plain text but required if we're encrypting
    to_keys = await get_to_keys(to_users=to_users,
                                ignore_missing=ignore_missing,
                                key_store=key_store)

    inbox_signer = None
    if inbox:
        inbox_signer = await get_user_signer(user=inbox,
                                             key_store=key_store)

    if loop is False:
        await post_single(relays=relays,
                          user_sign=user_signer,
                          to_users_k=to_keys,
                          inbox_sign=inbox_signer,
                          inbox_kind=inbox_kind,
                          is_encrypt=is_encrypt,
                          subject=subject,
                          message=message,
                          kind=kind,
                          tags=tags
                          )

    else:
        await post_loop(relays=relays,
                        user_sign=user_signer,
                        to_users_k=to_keys,
                        inbox_sign=inbox_signer,
                        inbox_kind=inbox_kind,
                        is_encrypt=is_encrypt,
                        subject=subject,
                        kind=kind,
                        tags=tags
                        )


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.FATAL)
    util_funcs.create_work_dir(WORK_DIR)
    try:
        asyncio.run(main(get_args()))
    except ConfigError as ce:
        print(ce)
    except DecryptionException as de:
        print(f'bad password or non encrypted store? - {de}')




