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

def do_post(client: Client,
            post_app: PostApp,
            msg):

    client.start()
    while not post_app.connection_status:
        time.sleep(0.2)
    post_app.do_post(msg)
    client.end()


def show_post_info(as_user: Profile,
                   msg, to_users, is_encrypt, subject,
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
        opts, args = getopt.getopt(sys.argv[1:], 'ha:t:piles:r:e:v:', ['help',
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
            if o in ('-i', '--ignore_missing'):
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
            elif o in ('-l', '--loop'):
                ret['loop'] = True

        if ret['user'] is None and len(args) > 0:
            ret['user'] = args.pop(0)
        if args:
            ret['message'] = ' '.join(args)

    except getopt.GetoptError as e:
        print(e)
        usage()

    return ret


def get_user_keys(user: str) -> Keys:

    if user is None:
        raise ConfigException('no user supplied')
    elif user == '?':
        ret = Keys()
        print('created adhoc key - %s/%s' % (ret.public_key_hex(),
                                             ret.public_key_bech32()))
    else:
        try:
            ret = Keys.get_key(user)
            if ret is None:
                raise Exception()

        except Exception as e:
            raise ConfigException('unable to create keys using - %s' % user)

        if ret.private_key_hex() is None:
            raise ConfigException('unable to create private keys using - %s' % user)

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
                    logging.info('unable to create keys for to user using - %s - ignoring' % c_to)
                else:
                    raise ConfigException('unable to create keys for to user using - %s' % c_to)

        if not ret:
            raise ConfigException('unable to create any to user keys!')

    return ret


def post_single(relays: [str],
                user: Keys,
                to_users: Keys,
                inbox: Keys,
                is_encrypt: bool,
                subject: str,
                message: str):

    k: Keys

    with ClientPool(relays) as c:
        # bit hacky... connected means only that we're connected to atleast 1 of the relays in the pool
        # when we publish theirs no guarantee that post will make it to all relays...
        while c.connected is False:
            time.sleep(0.1)

        to_post = []

        if is_encrypt:
            for k in to_users:
                post_event = Event(kind=Event.KIND_ENCRYPT,
                                   pub_key=user.public_key_hex(),
                                   content=message)
                evt_tags = [['p', k.public_key_hex()]]
                if subject:
                    evt_tags.append(['subject', subject])
                post_event.tags = evt_tags

                post_event.content = post_event.encrypt_content(priv_key=user.private_key_hex(),
                                                                pub_key=k.public_key_hex())
                to_post.append(post_event)

        else:
            post_event = Event(kind=Event.KIND_TEXT_NOTE,
                               pub_key=user.public_key_hex(),
                               content=message)

            evt_tags = []
            if subject:
                evt_tags.append(['subject', subject])
            if to_users:
                evt_tags = evt_tags + [['p', k.public_key_hex()] for k in to_users]

            post_event.tags = evt_tags

            to_post.append(post_event)

        c_evt: Event
        for c_evt in to_post:
            c_evt.sign(user.private_key_hex())
            c.publish(c_evt)





def run_post():
    opts = get_options()
    user = opts['user']
    to_users = opts['to_users']
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

        if opts['loop'] is False:
            post_single(relays=opts['relay'],
                        user=user_keys,
                        to_users=to_keys,
                        inbox=None,
                        is_encrypt=opts['is_encrypt'],
                        subject=opts['subject'],
                        message=opts['message']
                        )


    except ConfigException as ce:
        print(ce)




if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    run_post()

