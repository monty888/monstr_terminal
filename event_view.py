import logging
import sys
import signal
import asyncio
import argparse
from pathlib import Path
from datetime import datetime, timedelta
import aioconsole
from monstr.ident.profile import Profile, Contact, NIP5Helper, NIP5Error
from monstr.ident.event_handlers import NetworkedProfileEventHandler, ProfileEventHandlerInterface
from monstr.ident.alias import ProfileFileAlias
from monstr.client.client import ClientPool, Client
from monstr.client.event_handlers import DeduplicateAcceptor, LengthAcceptor, NotOnlyNumbersAcceptor, EventHandler, LastEventHandler
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
RELAYS = None
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
# default output event kinds
KINDS = f'{Event.KIND_TEXT_NOTE},{Event.KIND_ENCRYPT}'
# for non contacts event must reach this pow to be output
POW = None
# how events should be output
OUTPUT = 'formatted'

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
    as_user: Profile = None
    all_view = []
    view_extra = []
    inboxes = []
    inbox_keys = []
    shared_keys = []
    tags = config['tags']

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
            raise ConfigError(f'unable to find/create as_user profile - {config["as_user"]}')

        all_view.append(as_user)

        c_c: Contact
        await profile_handler.load_contacts(as_user)
        contacts = as_user.contacts
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

    # extract
    until = config['until']
    try:
        if config['until'] is not None:
            until = int(config['until'])
    except ValueError as e:
        raise ConfigError(f'until - {config["until"]} not a numeric value')


    # kind of events that'll we output
    try:
        kinds = {int(v) for v in config['kinds'].split(',')}
    except ValueError as e:
        raise ConfigError(f'kinds should be integer values got {config["kinds"]}')

    if tags:
        if tags == 'none':
            tags = None
        else:
            tags = tags.split(',')

    # mentioned events
    if config['eid']:
        config['eid'] = config['eid'].split(',')
        for c_id in config['eid']:
            if not Event.is_event_id(c_id):
                raise ConfigError(f'id mentioned event does\'t look like a valid event id {config["kinds"]}')

    config.update({
        'as_user': as_user,
        'all_view': all_view,
        'view_extra': view_extra,
        'inboxes': inboxes,
        'inbox_keys': inbox_keys,
        'shared_keys': shared_keys,
        'since': since,
        'until': until,
        'kinds': kinds,
        'tags': tags
    })
    return config


class MyClassifier:

    def __init__(self,
                 event_ids: [str] = None,
                 as_user: Profile = None,
                 view_profiles: [Profile] = None,
                 public_inboxes: [Profile] = None):

        self._as_user = as_user
        self._view_profiles = view_profiles
        self._inboxes = public_inboxes
        self._view_keys = []
        self._make_view_keys()
        self._event_ids = event_ids

    @property
    def view_keys(self):
        return self._view_keys

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

    def classify(self, evt: Event):
        # we requested it but it might still be considered spam, we mark here
        # if maybe spam is returned then extra test on event might happen
        # currently nip5 check
        ret = 'maybe spam'

        # we specifically asked for this event
        if self._event_ids and evt.id in self._event_ids:
            ret = 'good'

        # event pub_k it to or from keys we have specificly mentioned
        elif evt.pub_key in self._view_keys or \
                self._as_user is not None and \
                (self._as_user.public_key in evt.pub_key or self._as_user.public_key in evt.p_tags):
            ret = 'good'

        return ret


class PrintEventHandler(EventHandler):
    """
       print handler
       printer should be a class with a print_event(Event) method
    """
    def __init__(self,
                 event_acceptors=[],
                 profile_handler: ProfileEventHandlerInterface = None,
                 printer=None,
                 classifier=None,
                 nip5helper:NIP5Helper = None,
                 nip5=False,
                 pow=False):

        self._profile_handler = profile_handler
        self._printer = printer
        self._classifier: MyClassifier = classifier
        self._nip_checker: NIP5Helper = nip5helper
        self._pow = pow
        self._nip5 = nip5
        super().__init__(event_acceptors)

    async def _printer_event_if_nip5(self, evt: Event):
        p: Profile = await self._profile_handler.get_profile(evt.pub_key)
        try:
            if await self._nip_checker.is_valid_profile(p):
                await self._printer.print_event(evt)
        except NIP5Error as ne:
            logging.debug(f'PrintEventHandler::_printer_event_if_nip5 ignored event {evt.id} publisher has bad nip5')

    async def _profiles_prefetch(self, events: [Event]):
        ukeys = set()
        for c_evt in events:
            ukeys.add(c_evt.pub_key)
            for c_tag in c_evt.p_tags:
                ukeys.add(c_tag)
        await self._profile_handler.get_profiles(list(ukeys),
                                                 create_missing=True)

    async def ado_event(self, the_client: Client, sub_id, evt: Event):
        c_evt: Event
        if isinstance(evt, Event):
            evt = [evt]

        to_print = []
        for c_evt in evt:
            if self.accept_event(the_client, sub_id, c_evt):
                to_print.append(c_evt)

        if not to_print:
            return

        Event.sort(to_print, inplace=True, reverse=False)
        await self._profiles_prefetch(to_print)

        for c_evt in to_print:
            if self._classifier:
                rating = self._classifier.classify(c_evt)
                # good events will output always
                # maybe spam events will pass
                #   if pow and nip5 are both false
                #   if pow is true and nip5 is false
                #   if pow is false and nip5 is true and nip5 validates
                #   if pow is true and nip5 is true and nip5 validates
                if rating == 'good' or (self._pow is False and self._nip5 is False):
                    await self._printer.print_event(c_evt)
                elif self._pow and self._nip5 is False:
                    await self._printer.print_event(c_evt)
                elif self._nip5:
                    await self._printer_event_if_nip5(c_evt)

    def do_event(self, the_client: Client, sub_id, evt: Event):
        # client only supports sync do_event - maybe change?
        asyncio.create_task(self.ado_event(the_client, sub_id, evt))


class JSONPrinter:
    # outputs event in raw format
    async def print_event(self, evt: Event):
        await aioconsole.aprint(evt.event_data())


class ContentPrinter:
    # output just the content of an event
    async def print_event(self, evt: Event):
        await aioconsole.aprint(evt.content)


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
    parser.add_argument('-i', '--id', action='store', default=args['eid'], dest='eid',
                        help=f"""
                                    comma separated event ids will be added as e tag filter e.g with kind=42 
                                    can be used to view a chat channel,
                                    default[{args['eid']}]""")
    parser.add_argument('-k', '--kinds', action='store', default=args['kinds'],
                        help=f"""
                                comma separated event kinds to output,
                                default[{args['kinds']}]""")
    parser.add_argument('-s', '--since', action='store', default=args['since'], type=int,
                        help=f'show events n hours previous to running, default [{args["since"]}]')
    parser.add_argument('-u', '--until', action='store', default=args['until'], type=int,
                        help=f'show events n hours after since, default [{args["until"]}]')
    parser.add_argument('--pubkey', action='store_true', default=args['pubkey'],
                        help=f"""
                                        output event author pubkey
                                        default[{args['pubkey']}]""")
    parser.add_argument('-t', '--tags', action='store', default=args['tags'],
                        help=f"""
                                    comma separated tag types to output, =* for all
                                    default[{args['tags']}]""")

    parser.add_argument('-p', '--pow', action='store', choices=[8,12, 16, 20, 24, 28, 32], default=args['pow'],
                        type=int,
                        help=f"""
                                        minimum amount required for events excluding contacts of as_user
                                        default[{args['pow']}]""")

    parser.add_argument('-e', '--entities', action='store_true',
                        help='output event_id and pubkeys as nostr entities',
                        default=args['nip5'])
    parser.add_argument('--nip5check', action='store_true',
                        help='nip5 checked and displayed green if good',
                        default=args['nip5'])
    parser.add_argument('-n', '--nip5', action='store_true', help='valid nip5 required for events excluding contacts of as_user',
                        default=args['nip5'])
    parser.add_argument('-o', '--output', action='store', choices=['formatted', 'json', 'content'], default=args['output'],
                        help=f"""
                                        how to display events
                                        default[{args['output']}]""")
    parser.add_argument('--ssl_disable_verify', action='store_true', help='disables checks of ssl certificates')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output', default=args['debug'])

    ret = parser.parse_args()

    # so --as_user opt can be overridden empty if its defined in config file
    if ret.as_user =='' or ret.as_user.lower() == 'none':
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
        'kinds': KINDS,
        'pow': POW,
        'nip5': False,
        'nip5check': False,
        'pubkey': False,
        'tags': None,
        'eid': None,
        'output': OUTPUT,
        'ssl_disable_verify': None,
        'entities': False,
        'debug': False,
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


def get_event_filters(view_profiles: [Profile],
                      since: datetime,
                      until: int = None,
                      mention_eids: [str] = None,
                      kinds: [int] = [Event.KIND_TEXT_NOTE, Event.KIND_ENCRYPT],
                      pow: int = None):

    ret = []
    watch_keys = []
    c_p: Profile

    if view_profiles:
        for c_p in view_profiles:
            watch_keys.append(c_p.public_key)

    # watch both from and mention for these keys
    if watch_keys:
        # events from accounts we follow, pow if any, not applied
        ret.append({
            'authors': watch_keys
        })
        # events to/mention accounts we follow, pow if any, applied
        ret.append({
            '#p': watch_keys
        })
        if pow:
            ret.append({})

    # more general filter, even with watchkeys we need to use this if nip5
    # because we want events not in are watch keys to test against nip5
    # which can't be done from a filter alone
    else:
        ret.append({})

    # add common filter paras to all filters
    for c_f in ret:
        # since and kinds always added
        c_f['since'] = util_funcs.date_as_ticks(since)
        c_f['kinds'] = kinds

        # other fields that may be added
        if until:
            c_f['until'] = until
        if mention_eids:
            c_f['#e'] = mention_eids
        # pow added if we didn't specify authors, this include to filter
        # (pow is applied to events sent/mentioning authors we asked for)
        if pow and 'authors' not in c_f:
            c_f['ids'] = [''.join(['0'] * (int(pow / 4)))]

    # any requested eventids we'll fetch regardless of by who or when
    if mention_eids:
        ret.append({
            'ids': mention_eids
        })

    return ret


async def main(args):

    # connect to these relay
    relay = args['relay'].split(',')

    # disable ssl checks
    ssl = None
    if args['ssl_disable_verify']:
        ssl = False

    # start and connect relays
    my_client = ClientPool(relay, ssl=ssl)
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

    # if this is true then output is just the json as we recieve ot
    output = config['output']

    # the event kinds that we subscribe to and output
    view_kinds = config['kinds']

    # bits of pow to events from any accounts we didn't request
    pow = config['pow']

    # nip5 required for events from any accounts we didn't request
    # if both pow and nip5 are requested then both needed for those events to be output
    nip5 = config['nip5']
    nip5check = config['nip5check']

    # used if we are spam checking with nip5 or if we are verifying nip5s for display
    nip5helper = NIP5Helper()


    # only view events that mention this event
    mention_eids = config['eid']

    # actually show event author pubkey
    show_pubkey = config['pubkey']

    # output these event tags
    show_tags = config['tags']

    # output the event id and pubkey as note or npub style
    entities = config['entities']

    # keep track of last events seen so we can reconnect without getting same events again
    last_event_track = LastEventHandler()

    # just a wrap around get_event_filters so we don't have to call with all the
    # fields all the time
    def my_get_event_filters(with_since):
        # sub for what we'll output to screen
        # TODO: not checked but I think if using inbox you always need to fetch type 4s
        fetch_kinds = list(view_kinds)
        if inboxes and Event.KIND_ENCRYPT not in fetch_kinds:
            fetch_kinds.append(Event.KIND_ENCRYPT)

        return get_event_filters(view_profiles=view_profiles,
                                 since=with_since,
                                 until=until,
                                 mention_eids=mention_eids,
                                 kinds=fetch_kinds,
                                 pow=pow)

    async def print_run_info():
        c_p: Profile
        c_c: Contact
        print(f'using relays {relay}')
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

        print(f'showing events of kind {view_kinds} from now minus {since} hours')
        if until:
            print(f'until {until} hours from this point')

        print(f'pow for non follows ({pow}) and nip5 check ({nip5})')

    # show run info
    await print_run_info()
    # change to since to point in time
    since = datetime.now() - timedelta(hours=since)

    since_url = {}

    # same for util if it is a value, which is taken as hours from since
    if until:
        until = util_funcs.date_as_ticks(since + timedelta(hours=until))

    def my_connect(the_client: Client):
        # so on reconnect we don't ask for everything again
        use_since = since

        if last_event_track.get_last_event_dt(the_client):
            use_since = last_event_track.get_last_event_dt(the_client)

        # sub just for keeping profiles upto date
        the_client.subscribe(handlers=[profile_handler,
                                       last_event_track],
                             filters=[
            {
                'kinds': [Event.KIND_META],
                'since': util_funcs.date_as_ticks(datetime.now())
            }
        ])

        # get the event filter with since
        event_filter = my_get_event_filters(with_since=use_since)

        the_client.subscribe(handlers=[print_handler,
                                       last_event_track],
                             filters=event_filter)

    # actually does the outputting
    if output == 'json':
        my_printer = JSONPrinter()
    elif output == 'formatted':
        # by default we won't valid the nip5s for display
        fnip_check = None
        if nip5check:
            fnip_check = nip5helper

        my_printer = FormattedEventPrinter(profile_handler=profile_handler,
                                           as_user=as_user,
                                           inbox_keys=inbox_keys,
                                           share_keys=share_keys,
                                           show_pub_key=show_pubkey,
                                           show_tags=show_tags,
                                           entities=entities,
                                           nip5helper=fnip_check)
    elif output == 'content':
        my_printer = ContentPrinter()

    # event handler for printing events
    print_handler = PrintEventHandler(profile_handler=profile_handler,
                                      event_acceptors=[DeduplicateAcceptor(),
                                                       LengthAcceptor(),
                                                       NotOnlyNumbersAcceptor()],
                                      printer=my_printer,
                                      classifier=MyClassifier(event_ids=mention_eids,
                                                              as_user=as_user,
                                                              view_profiles=view_profiles,
                                                              public_inboxes=inboxes),
                                      nip5helper=nip5helper,
                                      pow=pow is not None,
                                      nip5=nip5)

    # we end and reconnect - bit hacky but just makes thing easier to set in action
    my_client.set_on_connect(my_connect)

    # do a single query to get stored events that match, this allows us to sort
    # it might be slower because we're waiting for all clients to return eose
    # or atleast fail, but the output is less confusing timewise as before a fast relay
    # might have returned all its events before another one that only has a few older events
    # but these would have been the last shown
    the_events = await my_client.query(filters=my_get_event_filters(with_since=since),
                                       do_event=last_event_track.do_event)

    await print_handler.ado_event(
        the_client=None,
        sub_id=None,
        evt=the_events)

    print('*** listening for more events ***')
    for c_client in my_client:
        my_client.set_on_eose(print_handler.do_event)
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
