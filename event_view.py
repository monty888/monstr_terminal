"""
usage: event_view.py [-h] [-r RELAY] [-a AS_USER] [--view_profiles VIEW_PROFILES] [-v VIA]
                     [-s SINCE] [-u UNTIL] [-d]

view nostr events from the command line

options:
  -h, --help            show this help message and exit
  -r RELAY, --relay RELAY
                        comma separated nostr relays to connect to, default[wss://nos.lol]
  -a AS_USER, --as_user AS_USER
                        alias, priv_k or pub_k of user to view as. If only created from
                        pub_k then kind 4 encrypted events will be left encrypted,
                        default[monty]
  --view_profiles VIEW_PROFILES
                        additional comma separated alias, priv_k or pub_k of user to view,
                        default[None]
  -v VIA, --via VIA     additional comma separated alias(with priv_k) or priv_k that will be
                        used as public inbox with wrapped events, default[None]
  -s SINCE, --since SINCE
                        show events n hours previous to running, default [6]
  -u UNTIL, --until UNTIL
                        show events n hours after since, default [None]
  -d, --debug           enable debug output

"""
import logging
import sys
import signal
import asyncio
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from monstr.ident.profile import Profile, Contact
from monstr.ident.event_handlers import NetworkedProfileEventHandler, ProfileEventHandlerInterface
from monstr.ident.alias import ProfileFileAlias
from monstr.client.client import ClientPool, Client
from monstr.client.event_handlers import PrintEventHandler, EventAccepter, DeduplicateAcceptor, LengthAcceptor, NotOnlyNumbersAcceptor
from monstr.util import util_funcs
from monstr.event.event import Event
from monstr.encrypt import Keys
from app.post import PostApp
from cmd_line.util import FormattedEventPrinter
from util import ConfigError, load_toml

# defaults if not otherwise given
# working directory it'll be created it it doesn't exist
WORK_DIR = f'{Path.home()}/.nostrpy/'
# relay/s to attach to
RELAYS = 'ws://localhost:8081'
# user to view as
AS_USER = None
# additional profiles to view other than as_user and anyone they follow
VIEW_EXTRA = None
# look in these 'inboxes' also
INBOXES = None
# number of hours to look back at star up
SINCE = 6
# get events until - note if using until there's not really any point staying running as new events won't come in!
UNTIL = None
# so we can just use a file
CONFIG_FILE = f'{WORK_DIR}event_view.toml'


def get_profiles_from_keys(keys: str,
                           private_only=False,
                           single_only=False,
                           alias_map: ProfileFileAlias = None) -> [Keys]:
    """
    :param alias_map:
    :param keys:            , seperated nsec/npub
    :param private_only:    only accept nsec
    :param single_only:     only a single key
    :return:
    """
    if single_only:
        keys = [keys]
    else:
        keys = keys.split(',')

    ret = []
    for c_key in keys:
        # maybe have flag to allow hex keys but for now just nsec/npub as it's so easy to leak the priv_k otherwise!
        if Keys.is_bech32_key(c_key):
            the_key = Keys.get_key(c_key)

        # is it an alias?
        elif alias_map:
            p: Profile = alias_map.get_profile(c_key)
            if p:
                the_key = p.keys
            else:
                raise ConfigError('%s doesn\'t look like a nsec/npub nostr key or alias not found' % c_key)
        else:
            raise ConfigError('%s doesn\'t look like a nsec/npub nostr key' % c_key)

        if private_only and the_key.private_key_hex() is None:
            raise ConfigError('%s is not a private key' % c_key)
        ret.append(the_key)
    return ret


async def get_from_config(config,
                          profile_handler: ProfileEventHandlerInterface):
    as_user = None
    all_view = []
    view_extra = []
    inboxes = []
    inbox_keys = []
    shared_keys = []

    # TODO allow the alias file to be changed
    alias_file = '%sprofiles.csv' % WORK_DIR
    alias_map = ProfileFileAlias(alias_file)
    # user we're viewing as
    if config['as_user'] is not None:
        user_key = get_profiles_from_keys(config['as_user'],
                                          private_only=False,
                                          single_only=True,
                                          alias_map=alias_map)[0]

        as_user = await profile_handler.get_profile(user_key.public_key_hex(),
                                                    create_missing=True)

        # if we were given a private key then we'll attach it to the profile so it can decode msgs
        if user_key.private_key_hex():
            as_user.private_key = user_key.private_key_hex()

        if not as_user:
            raise ConfigError('unable to find/create as_user profile - %s' % config['as_user'])

        c_c: Contact
        contacts = await profile_handler.load_contacts(as_user)
        if contacts:
            contact_ps = await profile_handler.get_profiles(pub_ks=[c_c.contact_public_key for c_c in contacts],
                                                            create_missing=True)

            all_view = all_view + contact_ps.profiles

    # addtional profiles to view other than current profile
    if config['view_profiles']:
        view_keys = get_profiles_from_keys(config['view_profiles'],
                                           private_only=False,
                                           single_only=False,
                                           alias_map=alias_map)

        view_ps = await profile_handler.get_profiles(pub_ks=[k.public_key_hex() for k in view_keys],
                                                     create_missing=True)

        all_view = all_view + view_ps.profiles
        view_extra = view_ps.profiles

    # public inboxes for encrypted messages
    if config['via']:
        # NOTE without as_user we can only see plain texts in this account
        # if as_user is None:
        #     raise ConfigException('inbox can only be used with as_user set')

        inbox_keys = get_profiles_from_keys(config['via'],
                                            private_only=True,
                                            single_only=False,
                                            alias_map=alias_map)

        inboxes = await profile_handler.get_profiles(pub_ks=[k.public_key_hex() for k in inbox_keys],
                                                     create_missing=True)
        inboxes = inboxes.profiles
        all_view = all_view + inboxes

    if as_user is not None and as_user.private_key:
        shared_keys = PostApp.get_clust_shared_keymap_for_profile(as_user, all_view)

    try:
        since = int(config['since'])
    except ValueError as e:
        raise ConfigError('since - %s not a numeric value' % config['since'])


    until = config['until']
    try:
        if config['until'] is not None:
            until = int(config['until'])
    except ValueError as e:
        raise ConfigError('until - %s not a numeric value' % config['until'])

    return {
        'as_user': as_user,
        'all_view': all_view,
        'view_extra': view_extra,
        'inboxes': inboxes,
        'inbox_keys': inbox_keys,
        'shared_keys': shared_keys,
        'since': since,
        'until': until
    }


class MyAccept(EventAccepter):

    def __init__(self,
                 as_user: Profile = None,
                 view_profiles: [Profile] = None,
                 public_inboxes: [Profile] = None,
                 since=None):

        self._as_user = as_user
        self._view_profiles = view_profiles
        self._inboxes = public_inboxes

        self._view_keys = []
        self._make_view_keys()
        self._since = since

    def _make_view_keys(self):
        c_c: Contact
        c_p: Profile

        if self._as_user is not None:
            self._view_keys.append(self._as_user.public_key)
            self._view_keys = self._view_keys + [c_c.contact_public_key for c_c in self._as_user.contacts]

        if self._view_profiles is not None:
            self._view_keys = self._view_keys + [c_p.public_key for c_p in self._view_profiles]

        if self._inboxes is not None:
            self._view_keys = self._view_keys + [c_p.public_key for c_p in self._inboxes]

    def accept_event(self, evt: Event) -> bool:
        if self._since is not None and evt.created_at < self._since:
            return False

        # for now we'll just deal with these, though there's no reason why we couldn't show details
        # for meta or contact events and possibly others
        if evt.kind not in (Event.KIND_ENCRYPT, Event.KIND_TEXT_NOTE):
            return False

        # no specific view so all events
        if not self._view_keys:
            return True
        else:
            return evt.pub_key in self._view_keys or \
                   self._as_user is not None and \
                   (self._as_user.public_key in evt.pub_key or self._as_user.public_key in evt.p_tags)


def get_cmdline_args(args) -> dict:
    parser = argparse.ArgumentParser(
        prog='event_view.py',
        description="""
            view nostr events from the command line
            """
    )
    parser.add_argument('-r', '--relay', action='store', default=args['relay'],
                        help=f'comma separated nostr relays to connect to, default[{args["relay"]}]')
    parser.add_argument('-a', '--as_user', action='store', default=args['as_user'],
                        help=f"""
                        alias, priv_k or pub_k of user to view as. If only created from pub_k then kind 4
                        encrypted events will be left encrypted, 
                        default[{args['as_user']}]""")
    parser.add_argument('--view_profiles', action='store', default=args['view_extra'],
                        help=f"""
                            additional comma separated alias, priv_k or pub_k of user to view,
                            default[{args['view_extra']}]""")
    parser.add_argument('-v', '--via', action='store', default=args['via'],
                        help=f"""
                            additional comma separated alias(with priv_k) or priv_k that will be used 
                            as public inbox with wrapped events,
                            default[{args['via']}]""")
    parser.add_argument('-s', '--since', action='store', default=args['since'], type=int,
                        help=f'show events n hours previous to running, default [{args["since"]}]')
    parser.add_argument('-u', '--until', action='store', default=args['until'], type=int,
                        help=f'show events n hours after since, default [{args["until"]}]')

    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output', default=args['debug'])

    ret = parser.parse_args()

    # so --as_user opt can be overridden empty if its defined in config file
    if ret.as_user=='' or ret.as_user.lower() == 'none':
        ret.as_user = None

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
        'as_user': AS_USER,
        'view_extra': VIEW_EXTRA,
        'via': INBOXES,
        'since': SINCE,
        'until': UNTIL,
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

    # connect to these relay
    relay = args['relay']

    # start and connect relays
    my_client = ClientPool(relay)
    asyncio.create_task(my_client.run())
    await my_client.wait_connect(timeout=10)

    profile_handler = NetworkedProfileEventHandler(client=my_client)

    # fills in config with data from nostr, e.g. follows for any as_user
    try:
        config = await get_from_config(args, profile_handler)
    except ConfigError as ce:
        print(ce)
        my_client.end()
        sys.exit(2)
    except Exception as e:
        print(e)
        my_client.end()
        sys.exit(2)

    as_user: Profile = config['as_user']
    view_profiles = config['all_view']
    inboxes = config['inboxes']
    inbox_keys = config['inbox_keys']
    share_keys = config['shared_keys']
    since = config['since']
    until = config['until']

    async def print_run_info():
        c_p: Profile
        c_c: Contact

        extra_view_profiles = config['view_extra']
        # output running info
        if as_user:
            print('events will be displayed as user %s' % as_user.display_name())
            print('--- follows ---')

            # this will group fetch all follow profiles so they won't be fetch individually
            # when we list
            await profile_handler.get_profiles(pub_ks=as_user.contacts.follow_keys(),
                                               create_missing=True)

            for f_k in as_user.contacts.follow_keys():
                c_p = await profile_handler.get_profile(f_k)
                if c_p:
                    print(c_p.display_name())
                else:
                    print(c_c.contact_public_key)
        else:
            print('runnning without a user')

        if extra_view_profiles:
            print('--- extra profiles ---')
            for c_p in extra_view_profiles:
                print(c_p.display_name())

        if inboxes:
            print('--- checking inboxes ---')
            for c_p in inboxes:
                print(c_p.display_name())

        print('showing events from now minus %s hours' % since)
        if until:
            print('until %s hours from this point' % until)
    # show run info
    await print_run_info()
    # change to since to point in time
    since = datetime.now() - timedelta(hours=since)

    since_url = {}

    # same for util if it is a value, which is taken as hours from since
    if until:
        until = util_funcs.date_as_ticks(since + timedelta(hours=until))

    def my_eose(the_client: Client, sub_id: str, events):
        # seems mutiple filters mean we get unpredictable order from the relay
        # we probably shouldn't rely on order from relay anyhow
        def my_sort(evt: Event):
            return evt.created_at_ticks
        events.sort(key=my_sort)
        # profile_handler.do_event(the_client,sub_id, events)

        # prfetch the profiles that we'll need
        async def do_events():
            c_evt: Event
            ukeys = set()
            for c_evt in events:
                ukeys.add(c_evt.pub_key)
                for c_tag in c_evt.p_tags:
                    ukeys.add(c_tag)


            # # force fetch of profiles
            await profile_handler.get_profiles(list(ukeys),
                                               create_missing=True)

            for c_evt in events:
                my_printer.do_event(the_client, sub_id, c_evt)

        asyncio.create_task(do_events())

    def my_connect(the_client: Client):
        # so on reconnect we don't ask for everthing again
        use_since = since
        if the_client.url in since_url:
            use_since = since_url[the_client.url]

        # filter for our main subscription
        my_filters = [
            # all metas from this point on
            {
                'kinds': [Event.KIND_META],
                'since': util_funcs.date_as_ticks(datetime.now())
            }
        ]

        # bit shit look at this
        # watch_keys = []
        # if as_user:
        #     watch_keys = as_user.contacts.follow_keys() + [as_user.public_key]
        # if inbox_keys:
        #     k: Keys
        #     for k in inbox_keys:
        #         watch_keys.append(k.public_key_hex())
        #
        #     # watch_keys = watch_keys + inbox_keys
        watch_keys = []
        if view_profiles:
            c_p: Profile
            for c_p in view_profiles:
                watch_keys.append(c_p.public_key)

        # watch both from and mention for these keys
        if watch_keys:
            # events from accounts we follow
            my_filters.append({
                'since': util_funcs.date_as_ticks(use_since),
                'kinds': [Event.KIND_TEXT_NOTE, Event.KIND_ENCRYPT],
                'authors': watch_keys
            })
            # events to/mention accounts we follow
            my_filters.append({
                'since': util_funcs.date_as_ticks(use_since),
                'kinds': [Event.KIND_TEXT_NOTE, Event.KIND_ENCRYPT],
                '#p': watch_keys
            })

        else:
            # all note and encrypt events
            my_filters.append({
                'since': util_funcs.date_as_ticks(use_since),
                'kinds': [Event.KIND_TEXT_NOTE, Event.KIND_ENCRYPT]
            })

        # if given add until filter to the note/encrypt event filters
        if until:
            for c_f in range(1,len(my_filters)):
                my_filters[c_f]['until'] = until

        # don't think this relay even exists anymore so rem
        # note in the case of wss://rsslay.fiatjaf.com it looks like author is required to receive anything
        # if the_client.url == 'wss://rsslay.fiatjaf.com':
        #    e_filter['authors'] = [p.public_key for p in view_profiles]

        the_client.subscribe(handlers=[profile_handler, my_printer], filters=my_filters)

        since_url[the_client.url] = datetime.now()

    # prints out the events - NotOnlyNumbersAcceptor to get rid of some spam,
    # probably if could accept whitelist
    my_printer = PrintEventHandler(profile_handler=profile_handler,
                                   event_acceptors=[DeduplicateAcceptor(),
                                                    LengthAcceptor(),
                                                    NotOnlyNumbersAcceptor(),
                                                    MyAccept(as_user=as_user,
                                                             view_profiles=view_profiles,
                                                             public_inboxes=inboxes,
                                                             since=since)])
    # we'll attach our own evt printer rather than basic 1 liner of PrintEventHandler
    my_print = FormattedEventPrinter(profile_handler=profile_handler,
                                     as_user=as_user,
                                     inbox_keys=inbox_keys,
                                     share_keys=share_keys)

    async def my_display(the_client: Client, sub_id: str, evt: [Event]):
        await my_print.print_event(evt)

    my_printer.display_func = my_display

    # we end and reconnect - bit hacky but just makes thing easier to set in action
    my_client.set_on_eose(my_eose)
    my_client.set_on_connect(my_connect)
    for c_client in my_client:
        # because we're already connected we'll call manually
        if c_client.connected:
            my_connect(c_client)

    while True:
        await asyncio.sleep(0.1)
    my_client.end()




if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)
    util_funcs.create_work_dir(WORK_DIR)
    def sigint_handler(signal, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)
    asyncio.run(main(get_args()))
