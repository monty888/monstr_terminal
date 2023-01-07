"""
    make notes from the command line see --help for more options
"""
from gevent import monkey
monkey.patch_all()
import logging
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
import getopt
from cachetools import TTLCache
from monstr.ident.profile import Profile, ProfileList
from monstr.ident.event_handlers import NetworkedProfileEventHandler
from monstr.client.client import ClientPool, Client
from monstr.event.event import Event, EventTags
from monstr.event.persist import ClientSQLEventStore, ClientMemoryEventStore
from app.post import PostApp
from cmd_line.post_loop_app import PostAppGui
from monstr.util import util_funcs
from monstr.encrypt import Keys
from exception import ConfigException


# TODO: also postgres
WORK_DIR = '%s/.nostrpy/' % Path.home()
# EVENT_STORE = ClientMemoryEventStore()
# EVENT_STORE = TransientEventStore()
# RELAYS = ['wss://rsslay.fiatjaf.com','wss://nostr-pub.wellorder.net']
# RELAYS = ['wss://rsslay.fiatjaf.com']
# RELAYS = ['ws://localhost:8081']
RELAYS = ['ws://localhost:8888']


def usage():
    print("""
usage:

    """)
    sys.exit(2)


def show_post_info(as_user: Profile,
                   msg:str,
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

def get_options():
    ret = {
        'relay': RELAYS,
        'is_encrypt': True,
        'ignore_missing': False,
        'user': None,
        'to_users': None,
        'inbox': None,
        'subject': None,
        'loop': False,
        'message': None
    }

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hda:t:piles:r:e:v:', ['help',
                                                                        'debug',
                                                                        'relay=',
                                                                        'as_profile=',
                                                                        'plain_text',
                                                                        'to=',
                                                                        'via=',
                                                                        'ignore_missing',
                                                                        'loop',
                                                                        'subject=',
                                                                        'event='])

        # attempt interpret action
        for o, a in opts:
            if o in ('-h', '--help'):
                usage()
            elif o in ('-d', '--debug'):
                logging.getLogger().setLevel(logging.DEBUG)
            elif o in ('-i', '--ignore_missing'):
                ret['ignore_missing'] = True
            elif o in ('-a', '--as_profile'):
                ret['user'] = a
            elif o in ('-t', '--to'):
                ret['to_users'] = a.split(',')
            elif o in ('-r', '--relay'):
                ret['relay'] = a.split(',')
            elif o in ('-p', '--plain_text'):
                ret['is_encrypt'] = False
            elif o in ('-s', '--subject'):
                ret['subject'] = a
            elif o in ('-v', '--via'):
                ret['inbox'] = a
            elif o in ('-l', '--loop'):
                ret['loop'] = True

        if ret['user'] is None and len(args) > 1:
            ret['user'] = args.pop(0)
        if args:
            ret['message'] = ' '.join(args)

    except getopt.GetoptError as e:
        print(e)
        usage()

    return ret


def create_key(key_val:str, for_desc: str):
    try:
        ret = Keys.get_key(key_val)
        if ret is None:
            raise Exception()

    except Exception as e:
        raise ConfigException('unable to create %s keys using - %s' % (for_desc,
                                                                       key_val))

    if ret.private_key_hex() is None:
        raise ConfigException('unable to create %s private keys using - %s' % (for_desc,
                                                                               key_val))
    return ret


def get_user_keys(user: str) -> Keys:

    if user is None:
        raise ConfigException('no user supplied')
    elif user == '?':
        ret = Keys()
        print('created adhoc key - %s/%s' % (ret.public_key_hex(),
                                             ret.public_key_bech32()))
    else:
        ret = create_key(user, 'user')

    return ret


def get_to_keys(to_users: [str], ignore_missing: bool) -> [Keys]:
    ret = []
    if to_users is not None:
        for c_to in to_users:
            try:
                cu_key = Keys.get_key(c_to)
                if cu_key is None:
                    raise Exception()
                ret.append(cu_key)
            except Exception as e:
                if ignore_missing:
                    logging.info('unable to create keys for to_user using - %s - ignoring' % c_to)
                else:
                    raise ConfigException('unable to create keys for to_user using - %s' % c_to)

        if not ret:
            raise ConfigException('unable to create any to user keys!')

    return ret


def get_inbox_keys(inbox: str) -> Keys:
    if inbox is None:
        return
    return create_key(inbox, 'user')


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


def get_poster(client: Client,
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
    peh.get_profiles(pub_ks=p_to_fetch, create_missing=True)

    # get the sending user profile
    user_p = peh.get_profile(pub_k=user_k.public_key_hex())
    # because relay doesn't know the private key
    user_p.private_key = user_k.private_key_hex()

    # and for the inbox, normally we wouldn't expect this to have a profile
    inbox_p = None
    if inbox_k:
        inbox_p = peh.get_profile(inbox_k.public_key_hex())
        # again the relay wouldn't know this
        inbox_p.private_key = inbox_k.private_key_hex()

    # get the to users profile if any
    to_users_p = None
    if to_users_k:
        to_users_p = peh.get_profiles([k.public_key_hex() for k in to_users_k])

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


def post_single(relays: [str],
                user_k: Keys,
                to_users_k: Keys,
                inbox_k: Keys,
                is_encrypt: bool,
                subject: str,
                message: str):

    with ClientPool(relays) as client:
        post_env = get_poster(client=client,
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


def post_loop(relays: [str],
              user_k: Keys,
              to_users_k: Keys,
              inbox_k: Keys,
              is_encrypt: bool,
              subject: str):

    sub_id: str = None
    con_status = None

    kinds = Event.KIND_ENCRYPT
    if is_encrypt is False:
        kinds = Event.KIND_TEXT_NOTE

    def do_sub():
        nonlocal sub_id

        filter = {
            'kinds': [kinds],
            'limit': 1000
        }
        if subject:
            filter['#subject'] = subject

        sub_id = my_client.subscribe(handlers=[post_app],
                                     filters=filter,
                                     sub_id=sub_id)

    def on_status(status):
        nonlocal con_status
        if con_status != status['connected']:
            con_status = status['connected']
            my_gui.draw_messages()

    with ClientPool(relays) as my_client:
        post_env = get_poster(client=my_client,
                              user_k=user_k,
                              to_users_k=to_users_k,
                              inbox_k=inbox_k,
                              is_encrypt=is_encrypt,
                              subject=subject)
        post_app: PostApp = post_env['post_app']
        my_gui = PostAppGui(post_app,
                            profile_handler=NetworkedProfileEventHandler(client=my_client))

        my_client.set_status_listener(on_status)


        do_sub()
        my_gui.run()



def run_post():
    opts = get_options()
    user = opts['user']
    to_users = opts['to_users']
    inbox = opts['inbox']
    ignore_missing = opts['ignore_missing']
    loop = opts['loop']
    message = opts['message']
    is_encrypt = opts['is_encrypt']
    try:
        if loop is False and message is None:
            raise ConfigException('no message supplied to post')

        user_keys = get_user_keys(user)

        if is_encrypt and to_users is None:
            raise ConfigException('to users is required for encrypted messages')

        to_keys = get_to_keys(to_users, ignore_missing)

        inbox_keys = get_inbox_keys(inbox)

        if opts['loop'] is False:
            post_single(relays=opts['relay'],
                        user_k=user_keys,
                        to_users_k=to_keys,
                        inbox_k=inbox_keys,
                        is_encrypt=opts['is_encrypt'],
                        subject=opts['subject'],
                        message=opts['message']
                        )
        else:
            post_loop(relays=opts['relay'],
                      user_k=user_keys,
                      to_users_k=to_keys,
                      inbox_k=inbox_keys,
                      is_encrypt=opts['is_encrypt'],
                      subject=opts['subject']
                      )

    except ConfigException as ce:
        print(ce)




if __name__ == "__main__":
    logging.getLogger().setLevel(logging.FATAL)
    run_post()

