import logging
import sys
import signal
import asyncio
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from monstr.ident.profile import Profile, Contact, NIP5Helper, NIP5Error
from monstr.ident.event_handlers import NetworkedProfileEventHandler, ProfileEventHandlerInterface
from monstr.ident.alias import ProfileFileAlias
from monstr.ident.profile import ContactList
from monstr.client.client import ClientPool, Client
from monstr.client.event_handlers import DeduplicateAcceptor, LengthAcceptor, \
    NotOnlyNumbersAcceptor, EventHandler, LastEventHandler, FilterAcceptor
from monstr.util import util_funcs, ConfigError
from monstr.inbox import Inbox
from monstr.encrypt import Keys
from monstr.signing import SignerInterface, BasicKeySigner
from monstr.event.event import Event
from monstr_terminal.cmd_line.util import FormattedEventPrinter, JSONPrinter, ContentPrinter
from monstr_terminal.util import load_toml, get_keys_from_str

# defaults if not otherwise given
# working directory it'll be created it it doesn't exist
WORK_DIR = f'{Path.home()}/.nostrpy/'
# relay/s to attach to
RELAYS = None
# user to view as
AS_USER = None
# if as user fetch contacts and add them to the view
VIEW_CONTACTS = True
# if query with author keys if we are looking for events sent from, sent to, or from and to those keys
DIRECTION = 'both'
# additional profiles to view other than as_user and anyone they follow
VIEW_EXTRA = None
# look in these 'inboxes' also
INBOXES = None
# max number of events to return init q
LIMIT = 20
# number of hours to look back at star up
SINCE = None
# get events until - note if using until there's not really any point staying running as new events won't come in!
UNTIL = None
# so we can just use a file
CONFIG_FILE = f'view.toml'
# default output event kinds
KINDS = f'{Event.KIND_TEXT_NOTE},{Event.KIND_ENCRYPT}'
# kinds that will be treted as encrypted
ENCRYPT_KINDS = f'{Event.KIND_ENCRYPT}'
# kind that inbox events are expected to be on - currently all have to be on the same kind
# so you'd need to run more than 1 viewer if you want to look into more than one inbox
# and they're using different inbox kinds
INBOX_KINDS = Event.KIND_ENCRYPT
# show only events contained in inboxes (wrapped events)
INBOX_ONLY = False
# for non contacts event must reach this pow to be output
POW = None
# wait for all relays before starting to output events?
START_MODE = 'all'
# how events should be output
OUTPUT = 'formatted'
# when to exit
EXIT = 'never'


def get_int_or_none(val: str, f_name: str) -> int:
    ret = None
    try:
        if val is not None:
            ret = int(val)
    except ValueError as e:
        if val.lower() != 'none':
            raise ConfigError(f'{f_name} - {val} not a numeric value')
    return ret


async def get_from_config(config,
                          profile_handler: ProfileEventHandlerInterface):
    as_user: Profile = None
    as_sign: SignerInterface = None
    all_view = []
    view_extra = []
    view_contact = []
    inbox_keys = []
    tags = config['tags']
    contacts = config['contacts']

    # TODO allow the alias file to be changed
    alias_file = '%sprofiles.csv' % WORK_DIR
    alias_map = ProfileFileAlias(alias_file)
    # user we're viewing as
    if config['as_user'] is not None:
        user_key = get_keys_from_str(config['as_user'],
                                     private_only=False,
                                     single_only=True,
                                     alias_map=alias_map)[0]
        # if we were given a private key then we can create a basic signer
        # so in future this could be something else e.g something external like nsec bunker
        # or hardware device (though that'd probably be pain just for viewing unless it
        # let you batch accept decrypts)
        if user_key.private_key_hex():
            as_sign = BasicKeySigner(user_key)

        as_user = await profile_handler.aget_profile(user_key.public_key_hex(),
                                                     create_missing=False)
        if as_user:
            all_view.append(as_user)
            # lookup and add contacts to view?
            if contacts:
                c_c: Contact
                await profile_handler.aload_contacts(as_user)
                contacts = as_user.contacts
                if contacts:
                    contact_ps = await profile_handler.aget_profiles(pub_ks=[c_c.contact_public_key for c_c in contacts],
                                                                     create_missing=True)
                    view_contact = contact_ps.profiles
                    all_view = all_view + contact_ps.profiles
        else:
            print(f'WARNING: unable to find as_user profile - {config["as_user"]},can\'t get follows')
            # continue with stubb as_user profile
            as_user = await profile_handler.aget_profile(user_key.public_key_hex(),
                                                         create_missing=True)
            as_user.contacts = ContactList(contacts=[],
                                           owner_pub_k=as_user.public_key)
            all_view.append(as_user)

    # addtional profiles to view other than current profile
    if config['view_extra']:
        view_keys = get_keys_from_str(config['view_extra'],
                                      private_only=False,
                                      single_only=False,
                                      alias_map=alias_map)

        view_ps = await profile_handler.aget_profiles(pub_ks=[k.public_key_hex() for k in view_keys],
                                                      create_missing=True)

        all_view = all_view + view_ps.profiles
        view_extra = view_ps.profiles

    # public inboxes for encrypted messages
    if config['via']:
        # NOTE without as_user we can only see plain texts in this account
        # if as_user is None:
        #     raise ConfigException('inbox can only be used with as_user set')

        inbox_keys = get_keys_from_str(config['via'],
                                       private_only=True,
                                       single_only=False,
                                       alias_map=alias_map)
        # look up inbox profiles, only done to see if they have a name other than using the pubk
        inboxes = await profile_handler.aget_profiles(pub_ks=[k.public_key_hex() for k in inbox_keys],
                                                      create_missing=True)

        inboxes = inboxes.profiles

        all_view = all_view + inboxes

    # check kinds and encrypt_kinds
    try:
        for k in {'kinds', 'encrypt_kinds'}:
            v = config[k].lower()
            # * for kinds means any
            if k == 'kinds' and v == '*':
                kind_set = None
            # none is valid for encrypt kinds
            elif k == 'encrypt_kinds' and v == 'none':
                kind_set = {}
            else:
                kind_set = {int(v) for v in v.split(',')}

            # update in the config
            config[k] = kind_set
    except ValueError as e:
        raise ConfigError(f'kinds should be integer values got {v}')

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
        'as_sign': as_sign,
        'all_view': all_view,
        'view_contact': view_contact,
        'view_extra': view_extra,
        # 'inboxes': inboxes,
        'inbox_keys': inbox_keys,
        'since': get_int_or_none(config['since'], 'since'),
        'until': get_int_or_none(config['until'], 'until'),
        'limit': get_int_or_none(config['limit'], 'limit'),
        'tags': tags
    })
    return config


class MyClassifier:

    def __init__(self,
                 event_ids: [str],
                 as_user: Profile,
                 view_contacts: bool,
                 view_profiles: [Profile],
                 public_inboxes: [Profile]):

        self._as_user = as_user
        self._view_contacts = view_contacts
        self._view_profiles = view_profiles
        self._inboxes = public_inboxes
        self._view_keys = []
        self._event_ids = event_ids

    async def make_ready(self):
        await self._make_view_keys()

    @property
    def view_keys(self):
        return self._view_keys

    async def _make_view_keys(self):
        c_c: Contact
        c_p: Profile
        c_i: Inbox

        if self._as_user is not None:
            self._view_keys.append(self._as_user.public_key)
            if self._view_contacts:
                self._view_keys = self._view_keys + [c_c.contact_public_key for c_c in self._as_user.contacts]

        if self._view_profiles is not None:
            self._view_keys = self._view_keys + [c_p.public_key for c_p in self._view_profiles]

        if self._inboxes is not None:
            self._view_keys = self._view_keys + [await c_i.pub_key for c_i in self._inboxes]

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
                 nip5helper: NIP5Helper = None,
                 nip5=False,
                 pow=False):

        self._profile_handler = profile_handler
        self._printer = printer
        self._classifier: MyClassifier = classifier
        self._nip_checker: NIP5Helper = nip5helper
        self._pow = pow
        self._nip5 = nip5

        # prints are queued
        self._print_queue = asyncio.Queue()
        asyncio.create_task(self._my_consumer())

        super().__init__(event_acceptors)

    async def _valid_nip5_event_pub(self, evt: Event) -> bool:
        ret = False
        p: Profile = await self._profile_handler.aget_profile(evt.pub_key)
        try:
            ret = await self._nip_checker.is_valid_profile(p)
        except NIP5Error as ne:
            logging.debug(f'PrintEventHandler::_printer_event_if_nip5 ignored event {evt.id} publisher has bad nip5')
        return ret

    async def _profiles_prefetch(self, events: [Event]):
        ukeys = set()
        for c_evt in events:
            ukeys.add(c_evt.pub_key)
            for c_tag in c_evt.p_tags:
                ukeys.add(c_tag)
        await self._profile_handler.aget_profiles(list(ukeys),
                                                  create_missing=True)

    async def ado_event(self, the_client: Client, sub_id, evt: list[Event]|Event):
        c_evt: Event
        if isinstance(evt, Event):
            evt = [evt]

        to_print = [
            c_evt for c_evt in evt if self.accept_event(the_client, sub_id, c_evt)
        ]
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

                do_print = rating == 'good' or \
                           (self._pow is False and self._nip5 is False) or \
                           (self._pow and self._nip5 is False) or \
                           (self._nip5 and await self._valid_nip5_event_pub(c_evt))

                if do_print:
                    await self._printer.aprint_event(the_client, sub_id, c_evt)

    async def astatus(self, status):
        await self._printer.astatus(status)

    def do_event(self, the_client: Client, sub_id, evt: Event):
        # add the the evt to the print queue
        self._print_queue.put_nowait((the_client, sub_id, evt))

    async def _my_consumer(self):
        try:
            while True:
                args = await self._print_queue.get()
                await self.ado_event(*args)
        except Exception as e:
            logging.debug(f'PrintEventHandler::_my_consumer - {e}')


def get_args() -> dict:
    """
    get args to use order is
        default -> toml_file -> cmd_line options

    so command line option is given priority if given

    :return: {}
    """

    ret = {
        'work_dir': WORK_DIR,
        'conf': CONFIG_FILE,
        'relay': RELAYS,
        'as_user': AS_USER,
        'as_sign': None,
        'contacts': VIEW_CONTACTS,
        'view_extra': VIEW_EXTRA,
        'via': INBOXES,
        'direction': DIRECTION,
        'limit': LIMIT,
        'since': SINCE,
        'until': UNTIL,
        'kinds': KINDS,
        'encrypt_kinds': ENCRYPT_KINDS,
        'inbox_kinds': INBOX_KINDS,
        'inbox_only': INBOX_ONLY,
        'pow': POW,
        'nip5': False,
        'nip5check': False,
        'pubkey': False,
        'match_tags': None,
        'hashtag': None,
        'tags': None,
        'eid': None,
        'start_mode': START_MODE,
        'output': OUTPUT,
        'ssl_disable_verify': None,
        'entities': False,
        'exit': EXIT,
        'debug': False,
    }

    # only done to get the work-dir and conf options if set
    ret.update(get_cmdline_args(ret))
    # now form config file if any
    ret.update(load_toml(ret['conf'], ret['work_dir']))

    # 2pass so that cmdline options override conf file options
    ret.update(get_cmdline_args(ret))

    # if debug flagged enable now
    if ret['debug'] is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(f'get_args:: running with options - {ret}')

    if not ret['relay']:
        print('Required argument relay is missing. Use -r or --relay')
        exit(1)

    if ret['inbox_only'] and ret['via'] is None:
        print('inbox-only is True bit no inbox defined user -v or --via')
        sys.exit(1)

    return ret


def get_cmdline_args(args) -> dict:
    parser = argparse.ArgumentParser(
        prog='event_view.py',
        description="""
            view nostr events from the command line
            """
    )
    parser.add_argument('-c', '--conf', action='store', default=args['conf'],
                        help=f'name com TOML file to use for configuration, default[{args["conf"]}]')
    parser.add_argument('--work-dir', action='store', default=args['work_dir'],
                        help=f'base dir for files used if full path isn\'t given, default[{args["work_dir"]}]')
    parser.add_argument('-r', '--relay', action='store', default=args['relay'],
                        help=f'comma separated nostr relays to connect to, default[{args["relay"]}]')
    parser.add_argument('-a', '--as-user', action='store', default=args['as_user'],
                        help=f"""
                        alias, priv_k or pub_k of user to view as. If only created from pub_k then kind 4
                        encrypted events will be left encrypted, 
                        default[{args['as_user']}]""")
    parser.add_argument('--contacts', action='store_true',
                        help='if --as-user lookup contacts and add to view',
                        default=args['contacts'])
    parser.add_argument('--no-contacts', action='store_false',
                        help='if --as-user DO NOT add contacts to view',
                        default=args['contacts'], dest='contacts')
    parser.add_argument('--view-extra', action='store', default=args['view_extra'],
                        help=f"""
                            additional comma separated alias, priv_k or pub_k of user to view,
                            default[{args['view_extra']}]""")
    parser.add_argument('-v', '--via', action='store', default=args['via'],
                        help=f"""
                            additional comma separated alias(with priv_k) or priv_k that will be used 
                            as public inbox with wrapped events,
                            default[{args['via']}]""")
    parser.add_argument('--direction', action='store', default=args['direction'],choices={'from', 'to', 'both'},
                        help=f"""
                                if query with author keys if we are looking for events sent from, sent to or both with those keys
                                default[{args['direction']}]""")
    parser.add_argument('-i', '--id', action='store', default=args['eid'], dest='eid',
                        help=f"""
                                    comma separated event ids will be added as e tag filter e.g with kind=42 
                                    can be used to view a chat channel,
                                    default[{args['eid']}]""")
    parser.add_argument('-k', '--kinds', action='store', default=args['kinds'],
                        help=f"""
                                comma separated event kinds to output,
                                default[{args['kinds']}]""")
    parser.add_argument('--encrypt-kinds', action='store', default=args['encrypt_kinds'],
                        help=f"""
                                    comma separated event kinds to be decrypted,
                                    default[{args['encrypt_kinds']}]""")
    parser.add_argument('--inbox-kinds', action='store', default=args['inbox_kinds'], type=int,
                        help=f"""
                                    kind to use for inbox events, applied to all inboxes
                                    default[{args['inbox_kinds']}]""")
    parser.add_argument('-l', '--limit', action='store', default=args['limit'],
                        help=f'max number of events to return, default [{args["limit"]}]')
    parser.add_argument('-s', '--since', action='store', default=args['since'],
                        help=f'show events n hours previous to running, default [{args["since"]}]')
    parser.add_argument('-u', '--until', action='store', default=args['until'],
                        help=f'show events n hours after since, default [{args["until"]}]')
    parser.add_argument('--hashtag', action='store', default=args['hashtag'],
                        help=f'only events with t tag value will be matched, default[{args["hashtag"]}]')
    parser.add_argument('--pubkey', action='store_true', default=args['pubkey'],
                        help=f"""
                                        output event author pubkey
                                        default[{args['pubkey']}]""")
    parser.add_argument('-t', '--tags', action='store', default=args['tags'],
                        help=f"""
                                    comma separated tag types to output, =* for all
                                    default[{args['tags']}]""")

    parser.add_argument('-p', '--pow', action='store', choices=[8, 12, 16, 20, 24, 28, 32], default=args['pow'],
                        type=int,
                        help=f"""
                                        minimum amount required for events excluding contacts of as_user
                                        default[{args['pow']}]""")

    parser.add_argument('-e', '--entities', action='store_true',
                        help='output event_id and pubkeys as nostr entities',
                        default=args['entities'])
    parser.add_argument('--no-entities', action='store_false',
                        help='do not output event_id and pubkeys as nostr entities',
                        default=(not args['entities']), dest='entities')
    parser.add_argument('--nip5check', action='store_true',
                        help='nip5 checked and displayed green if valid',
                        default=args['nip5check'])
    parser.add_argument('-n', '--nip5', action='store_true', help='valid nip5 required for events excluding contacts of as_user',
                        default=args['nip5'])
    parser.add_argument('--start-mode', choices=['all', 'first'],
                        default=args['start_mode'],
                        help=f"""
                                    at start wait for ALL relays to return events before starting to print or just FIRST 
                                    default[{args['start_mode']}]""")

    parser.add_argument('--inbox-only', action='store_true', help='only show events that are contained in inboxes',
                        default=args['inbox_only'])
    parser.add_argument('--no-inbox-only', action='store_false', help='events in and outside of inboxes will be shown',
                        default=args['inbox_only'])
    parser.add_argument('-o', '--output', action='store', choices=['formatted', 'json', 'content'], default=args['output'],
                        help=f"""
                                        how to display events
                                        default[{args['output']}]""")
    parser.add_argument('--ssl-disable-verify', action='store_true', help='disables checks of ssl certificates')
    # TODO add until option - if have until exit when we get event with timestamp >= that
    parser.add_argument('-x', '--exit', action='store',
                        default=args['exit'], choices=['never', 'store'],
                        help=f"""
                                            never - run indefinitely. store - exit after receiving stored events. 
                                            default[{args['exit']}]""")
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output', default=args['debug'])

    ret = parser.parse_args()
    # so --as_user opt can be overridden empty if its defined in config file
    if ret.as_user and (ret.as_user == '' or ret.as_user.lower() == 'none'):
        ret.as_user = None

    return vars(ret)


async def get_event_filters(view_profiles: [Profile],
                      since: datetime,
                      until: datetime,
                      limit: int,
                      mention_eids: [str],
                      kinds: [int],
                      hash_tag: str,
                      pow: int,
                      nip5: bool,
                      direction: str,
                      inboxes: [Inbox],
                      inbox_only: bool):

    ret = []
    watch_keys = []
    c_p: Profile
    c_i: Inbox

    # add the non-inbox view event filter
    if inbox_only is False:
        if view_profiles:
            for c_p in view_profiles:
                watch_keys.append(c_p.public_key)

        # watch both from and mention for these keys
        if watch_keys:
            # events from accounts we follow, pow if any, not applied
            if direction in {'both', 'from'}:
                ret.append({
                    'authors': watch_keys
                })

            if direction in {'both', 'to'}:

                ret.append({
                    '#p': watch_keys
                })

        # either not watching any particular authors or
        # we're going to allow unrequested events through based on
        # pow, nip5 or pow and nip5
        # note in case of nip5 alone you have to fetch all events anyhow so
        # probably best to use with at least a minimal pow
        if not watch_keys or pow or nip5:
            ret.append({})

    # add view into each inbox
    if inboxes:
        ret.append({
            # all have to be on same kind
            'kinds': [inboxes[0].kind],
            # inboxes are actually profile objs not inboxes here :(!
            'authors': [await c_i.pub_key for c_i in inboxes]
        })

    # add common filter paras to all filters
    for c_f in ret:
        # kinds addded unless we already added because its an inbox
        if kinds is not None and 'kinds' not in c_f:
            c_f['kinds'] = list(kinds)

        # other fields that may be added
        if limit:
            c_f['limit'] = limit
        if since:
            c_f['since'] = util_funcs.date_as_ticks(since)
        if until:
            c_f['until'] = util_funcs.date_as_ticks(until)
        if mention_eids:
            c_f['#e'] = mention_eids
        if hash_tag:
            c_f['#t'] = [hash_tag]

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


def output_rel_date(rel_date: datetime, the_date: datetime) -> str:
    """
        returns str output for the_date base on rel_date
        at the moment this just means if rel_date.date() == the_date.date()
        date output won't be output
    """
    if rel_date.date() == the_date.date():
        ret = the_date.strftime('%H:%M:%S')
    else:
        ret = the_date.strftime('%d/%m/%Y-%H:%M:%S')
    return ret


async def print_run_info(relay,
                         as_user,
                         contacts,
                         extra_view_profiles,
                         inboxes,
                         view_kinds,
                         encrypted_kinds,
                         since,
                         until,
                         limit,
                         pow,
                         nip5,
                         profile_handler,
                         direction,
                         inbox_only,
                         ):
    c_p: Profile
    c_c: Contact
    c_i: Inbox
    print(f'using relays {relay}')

    # output running info
    if as_user:
        print('events will be displayed as user %s' % as_user.display_name())
        if contacts:
            print('--- contacts ---')

            # this will group fetch all follow profiles so they won't be fetch individually
            # when we list
            await profile_handler.aget_profiles(pub_ks=as_user.contacts.follow_keys(),
                                                create_missing=True)

            for f_k in as_user.contacts.follow_keys()[:10]:
                c_p = await profile_handler.aget_profile(f_k)
                if c_p:
                    print(c_p.display_name())
                else:
                    print(c_c.contact_public_key)
            if len(as_user.contacts) > 10:
                print(f'and {len(as_user.contacts)-10} more...')
        else:
            print('contacts not added to view')

    else:
        print('runnning without a user')

    if extra_view_profiles:
        print('--- extra profiles ---')
        for c_p in extra_view_profiles:
            print(c_p.display_name())

    if inboxes:
        print(f'--- checking inboxes using kind {inboxes[0].kind} ---')
        for c_i in inboxes:
            print(await c_i.name)

    if view_kinds:
        filter_about = [f'showing events of kind {view_kinds}']
    else:
        filter_about = [f'showing events of kind any']

    if encrypted_kinds:
        filter_about.append(f' encrypted kinds {encrypted_kinds}')

    now = datetime.now()
    if since is not None:
        filter_about.append(f' from {output_rel_date(now, since)}')

    if until:
        filter_about.append(f' -> {output_rel_date(since, until)}')

    filter_about.append(f' limit {limit}')

    print(''.join(filter_about))

    print(f'pow for non follows ({pow}) and nip5 check ({nip5}) direction ({direction})')
    if inbox_only:
        print('!! inbox only !!')


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
    # await my_client.wait_connect(timeout=10,)

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

    # user that we running as, if this user has priv_k then where needed we'll do decryption and output plaintext
    as_user: Profile = config['as_user']
    as_sign = config['as_sign']

    # add add user contacts to view
    c_p: Profile
    view_contacts = config['contacts']
    view_contacts_profiles = config['view_contact']
    view_contacts_k = [c_p.keys for c_p in view_contacts_profiles]

    # extra profiles requested to view other than contacts of as_user or inboxes
    extra_view_profiles = config['view_extra']
    extra_view_k = [c_p.keys for c_p in extra_view_profiles]

    # just the keys of above, in most cases the keys are all we want - this is what we pass into outputters
    # for when they create the maps with inbox wrap events
    # probably we could put all ks in and use the same as we use on teh main filter but probably its not necessary
    # e.g. would you expect to use inbox and then look in that inbox for encrypted msgs with that inbox k?
    # everyone who has teh inbox k could look into them anyway so why?
    extra_and_contact_k = view_contacts_k + extra_view_k

    # all view profiles, contains all pub_ks that we're going to request from relay to make our view
    view_profiles = config['all_view']

    # the event kinds that we subscribe to and output
    view_kinds = config['kinds']

    # the event kinds that we will decrypt (we only add those that appear in view kinds)
    if view_kinds:
        encrypt_kinds = config['encrypt_kinds'].intersection(view_kinds)
    else:
        encrypt_kinds = config['encrypt_kinds']

    # the kind we'll use when looking for inbox events - same for all inboxes
    inbox_kinds = config['inbox_kinds']
    # in inbox only only events wrapped in given inboxes will be output
    inbox_only = config['inbox_only']

    # actually make into inbox objects
    inboxes = []

    inbox_keys: [Keys] = config['inbox_keys']
    c_k: Keys
    for c_k in inbox_keys:
        n_inbox = Inbox(signer=BasicKeySigner(c_k),
                        name=profile_handler.get_profile(c_k.public_key_hex()).display_name(),
                        use_kind=inbox_kinds)

        inboxes.append(n_inbox)

    # now set share map on inboxes if so we can see/decrypt encrypted message in them
    if as_sign:
        for c_i in inboxes:
            await c_i.set_share_map(for_sign=as_sign,
                                    to_keys=extra_and_contact_k)

    # sent from or to or both keys we've given
    direction = config['direction']

    # on startup wait for all relys before starting printout?
    start_mode = config['start_mode']

    # if this is true then output is just the json as we recieve ot
    output = config['output']

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

    # events from since point, after initial events this is updated
    # so on reconnect we don't go back and get all old events again
    since = config['since']
    if since is not None:
        since = datetime.now() - timedelta(hours=since)

    # until this date - note on reaching until date (maybe in the future)
    # we might as well exit or have option to exit as no more events will come in
    until = config['until']
    if until is not None:
        until = since + timedelta(hours=until)

    # if given only events with this t tag will be returned
    hash_tag = config['hashtag']

    # rough max limit of events at bootstrap (before live incoming events)
    limit = config['limit']

    # used to check that the events that we get back from relay match those we requested
    # the actual filter used is set when we add the filter in on_connect
    e_filter_acceptor = FilterAcceptor()

    # exit mode
    exit = config['exit']

    # just a wrap around get_event_filters so we don't have to call with all the
    # fields all the time
    async def my_get_event_filters(with_since):

        return await get_event_filters(view_profiles=view_profiles,
                                       since=with_since,
                                       until=until,
                                       limit=limit,
                                       mention_eids=mention_eids,
                                       kinds=view_kinds,
                                       pow=pow,
                                       nip5=nip5,
                                       direction=direction,
                                       hash_tag=hash_tag,
                                       inboxes=inboxes,
                                       inbox_only=inbox_only)

    # show run info except if we're outputting json
    if output != 'json':
        await print_run_info(relay=relay,
                             as_user=as_user,
                             contacts=view_contacts,
                             extra_view_profiles=extra_view_profiles,
                             inboxes=inboxes,
                             direction=direction,
                             view_kinds=view_kinds,
                             encrypted_kinds=encrypt_kinds,
                             since=since,
                             until=until,
                             limit=limit,
                             pow=pow,
                             nip5=nip5,
                             profile_handler=profile_handler,
                             inbox_only=inbox_only)

    def my_connect(the_client: Client):
        # so on reconnect we don't ask for everything again
        use_since = since

        if last_event_track.get_last_event_dt(the_client):
            use_since = last_event_track.get_last_event_dt(the_client)+timedelta(seconds=1)

        # sub just for keeping profiles upto date
        the_client.subscribe(handlers=[profile_handler,
                                       last_event_track],
                             filters=[
            {
                'kinds': [Event.KIND_META],
                'since': util_funcs.date_as_ticks(datetime.now())
            }
        ])

        asyncio.create_task(do_event_sub(the_client, use_since))

    async def do_event_sub(the_client: Client, use_since):
        # get the event filter with since
        event_filter = await my_get_event_filters(with_since=use_since)
        # set filter to the acceptor - if a relay gives us events that don't pass our filter we'll reject
        e_filter_acceptor.filter = event_filter
        # now subscribe
        the_client.subscribe(handlers=[last_event_track, print_handler],
                             filters=event_filter)

    # actually does the outputting
    if output == 'json':
        my_printer = JSONPrinter(as_sign=as_sign,
                                 inboxes=inboxes,
                                 encrypted_kinds=encrypt_kinds)
    elif output == 'formatted':
        # by default we won't valid the nip5s for display
        fnip_check = None
        if nip5check:
            fnip_check = nip5helper

        my_printer = FormattedEventPrinter(profile_handler=profile_handler,
                                           as_sign=as_sign,
                                           as_user=as_user,
                                           inboxes=inboxes,
                                           show_pub_key=show_pubkey,
                                           show_tags=show_tags,
                                           entities=entities,
                                           nip5helper=fnip_check,
                                           kinds=view_kinds,
                                           encrypted_kinds=encrypt_kinds)
    elif output == 'content':
        my_printer = ContentPrinter(as_sign=as_sign,
                                    inboxes=inboxes,
                                    encrypted_kinds=encrypt_kinds)

    # initial filter to get upto now
    boot_e_filter = await my_get_event_filters(with_since=since)

    # set inital accept criteria, this is a double check on what relays return
    # e_filter_acceptor.filter = boot_e_filter

    #
    my_classifier = MyClassifier(event_ids=mention_eids,
                                 as_user=as_user,
                                 view_contacts=view_contacts,
                                 view_profiles=view_profiles,
                                 public_inboxes=inboxes)
    await my_classifier.make_ready()
    # event handler for printing events
    print_handler = PrintEventHandler(profile_handler=profile_handler,
                                      event_acceptors=[DeduplicateAcceptor(),
                                                       e_filter_acceptor,
                                                       LengthAcceptor(),
                                                       NotOnlyNumbersAcceptor()
                                                       ],
                                      printer=my_printer,
                                      classifier=my_classifier,
                                      nip5helper=nip5helper,
                                      pow=pow is not None,
                                      nip5=nip5)

    """
        if order_first, then we wait to get events from each relay and then order them as a single set
        otherwise a slower relay returning later might make the events lookout of order date wise
        (note that its always possible to get out of date events but normally they should come in
        more or less forward in dates)
        without order first events will start printing as soon as the fastest relay returns
    """
    keep_running = True
    if start_mode == 'all':
        the_events = await my_client.query(filters=boot_e_filter,
                                           do_event=last_event_track.do_event,
                                           emulate_single=True,
                                           wait_connect=False)

        # because events may come from mutiple relays  sort
        Event.sort(the_events, inplace=True)

        # merge from multiple relays means that we can get more events than the limit
        # (different events from different relays - add opt to disable this force cut to limit?)
        if limit is not None:
            the_events = the_events[:limit]

        await print_handler.ado_event(
            the_client=None,
            sub_id=None,
            evt=the_events)

        keep_running = exit == 'never'
        if keep_running:
            await my_printer.astatus('*** listening for more events ***')

    else:

        def adhoc_do_event(the_client: Client, sub_id: str, events: [Event]):
            # events drawn in and they're recieved from each relay (minus duplicates)
            asyncio.create_task(print_handler.ado_event(
                the_client=None,
                sub_id=None,
                evt=events))
            last_event_track.do_event(the_client, sub_id, events)

        # called at query completetion - which might not be until timeout if we have bad relays
        def first_pull_complete():
            nonlocal keep_running
            keep_running = exit == 'never'
            if keep_running:
                asyncio.create_task(my_printer.astatus('*** listening for more events ***'))

        # TODO: fix client so that do event can be [handlers] and we wouldnt need adhoc_do_event
        await my_client.query(filters=boot_e_filter,
                              do_event=adhoc_do_event,
                              on_complete=first_pull_complete,
                              wait_connect=True,
                              emulate_single=False)

    for c_client in my_client:
        my_client.set_on_eose(print_handler.do_event)
        # because we're already connected we'll call manually
        if c_client.connected:
            my_connect(c_client)
            my_client.set_on_connect(my_connect)
    while keep_running:
        await asyncio.sleep(0.1)
    my_client.end()


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)
    util_funcs.create_work_dir(WORK_DIR)
    def sigint_handler(signal, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)
    asyncio.run(main(get_args()))
