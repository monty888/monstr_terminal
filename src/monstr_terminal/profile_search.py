"""
usage: profile_search.py [-h] [-r RELAY] [-a AS_USER] [-b BOOTSTRAP] [-s SINCE] [-d]

search for nostr user profiles

options:
  -h, --help            show this help message and exit
  -r RELAY, --relay RELAY
                        comma separated urls of relays to connect to - default ws://localhost:8081
  -a AS_USER, --as AS_USER
                        nsec/npub/hex or alias for account viewing as - default None
  -b BOOTSTRAP, --bootstrap BOOTSTRAP
                        nsec/npub/hex or alias for accounts used for bootstrapping - default None
  -s SINCE, --since SINCE
                        n days to search back for profile events - default 5
  -d, --debug           enable debug output


"""
import logging
import asyncio
import sys
import aioconsole
import argparse
from datetime import datetime, timedelta
from monstr.util import util_funcs
from monstr.ident.persist import MemoryProfileStore
from monstr.ident.event_handlers import NetworkedProfileEventHandler
from monstr.ident.profile import Profile, Contact
from monstr.ident.alias import ProfileFileAlias
from monstr_terminal.cmd_line.util import FormattedEventPrinter
from monstr.client.event_handlers import EventHandler
from monstr.client.client import ClientPool, Client
from monstr.event.event import Event
from monstr.encrypt import Keys
from monstr.exception import ConfigurationError
from pathlib import Path

# defaults if not otherwise given
# working directory it'll be created it it doesn't exist
WORK_DIR = '%s/.nostrpy/' % Path.home()
# relay/s to attach to
DEFAULT_RELAY = 'ws://localhost:8081'
# profiles persited here sqlite db
DB = WORK_DIR + 'monstr.db'
# nmae > key alias here
ALIAS_FILE = WORK_DIR + 'profiles.csv'
# how far to fetch metas back too in days
DEFAULT_SINCE = 5


def get_args():
    parser = argparse.ArgumentParser(
        prog='profile_search.py',
        description='search for nostr user profiles'
    )
    parser.add_argument('-r', '--relay', action='store', default=DEFAULT_RELAY,
                        help='comma separated urls of relays to connect to - default %s' % DEFAULT_RELAY)
    parser.add_argument('-a', '--as_user', action='store', default=None,dest='as_user',
                        help='nsec/npub/hex or alias for account viewing as - default %s' % None)
    parser.add_argument('-b', '--bootstrap', action='store', default=None,
                        help='nsec/npub/hex or alias for accounts used for bootstrapping - default %s' % None)
    parser.add_argument('-s', '--since', action='store', default=90, type=int,
                        help='n days to search back for profile events - default %s' % DEFAULT_SINCE)
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')

    ret = parser.parse_args()

    if ret.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    my_alias = ProfileFileAlias(ALIAS_FILE)
    p: Profile = None
    if ret.as_user:
        k = Keys.get_key(ret.as_user)
        if k is None:
            p = my_alias.get_profile(ret.as_user)
            if p is None:
                raise ConfigurationError('as_user - %s not nostr key and no matching alias' % ret.as_user)
            k = p.keys
        ret.as_user = k

    if ret.bootstrap:
        boot_keys = []
        for c_k in ret.bootstrap:
            k = Keys.get_key(c_k)
            if k is None:
                if p is None:
                    raise ConfigurationError('bootstrap - %s not nostr key and no matching alias' % c_k)
                k = p.keys
            boot_keys.append(k)
        ret.bootstrap = boot_keys

    return ret


async def display_profile(p: Profile,
                          profile_handler,
                          as_user,
                          output: str='short',
                          key_output='npub'):
    follows = ''
    follow_folow_count = ''
    c_contact: Contact
    f_p: Profile

    if as_user:
        if not as_user.contacts_is_set():
            await profile_handler.aload_contacts(as_user)
        # for marking those we follow
        if p.public_key in as_user.contacts.follow_keys():
            follows = 'F'

        count_ff = 0

        await profile_handler.get_profiles(pub_ks=as_user.contacts.follow_keys(),
                                           create_missing=True)
        for c_k in as_user.contacts.follow_keys():
            f_p = await profile_handler.get_profile(c_k)
            if f_p.contacts_is_set():
                if p.public_key in set(f_p.contacts.follow_keys()):
                    count_ff += 1

        follow_folow_count = 'FF%s' % count_ff

    pub_key = p.keys.public_key_bech32()
    if key_output != 'npub':
        pub_key = p.keys.public_key_hex()

    if output == 'short':
        await aioconsole.aprint(p.display_name(False)[0:15].rjust(15), ' - ', pub_key, ' ', follows, ' ', follow_folow_count)
    elif output == 'long':
        margin = 10
        await aioconsole.aprint('%s - %s' % ('name'.ljust(margin),
                                             p.display_name()))
        await aioconsole.aprint('%s - %s' % ('npub'.ljust(margin),
                                             p.keys.public_key_bech32()))
        await aioconsole.aprint('%s - %s' % ('hex'.ljust(margin),
                                             p.public_key))
        if p.get_attr('about'):
            await aioconsole.aprint('%s - %s' % ('about'.ljust(margin),
                                                 p.get_attr('about')))
        if p.get_attr('picture'):
            await aioconsole.aprint('%s - %s' % ('picture'.ljust(margin),
                                                 p.get_attr('picture')))
        if p.get_attr('banner'):
            await aioconsole.aprint('%s - %s' % ('banner'.ljust(margin),
                                                 p.get_attr('banner')))

        for c_attr in p.attrs:
            if c_attr not in ('picture', 'banner', 'name', 'about'):
                await aioconsole.aprint('%s - %s' % (('%s' % c_attr).ljust(margin),
                                                     p.get_attr(c_attr)))

        await aioconsole.aprint('%s - %s' % ('link'.ljust(margin),
                                             'https://hamstr.to/profile/%s' % p.keys.public_key_bech32()))


    else:
        await aioconsole.aprint(p.as_dict())


class My_EventHandler(EventHandler):

    def __init__(self,
                 profile_handler,
                 since):

        self._profile_handler = profile_handler
        self._since = since

        self._u_pubs_client = {}
        self._my_task = None

        super().__init__()

    @property
    def since(self):
        return self._since

    @since.setter
    def since(self, val):
        self._since = val

    def do_event(self, client: Client, sub_id, evt: [Event]):
        if isinstance(evt, Event):
            evt = [evt]

        if client.url not in self._u_pubs_client:
            self._u_pubs_client[client.url] = set()

        u_pubs = self._u_pubs_client[client.url]

        # if meta update now
        self._profile_handler.do_event(client, sub_id, Event.latest_events_only(evt))

        # for all other events extract pub_k and p_tag
        c_evt: Event
        other_events = [c_evt for c_evt in evt if c_evt.kind != Event.KIND_META]

        for c_evt in other_events:
            u_pubs.add(c_evt.pub_key)
            for pub_k in c_evt.p_tags:
                u_pubs.add(pub_k)

        async def do_fetches():
            await asyncio.sleep(0.2)

            to_fetch = u_pubs
            self._u_pubs_client[client.url] = set()

            for c_chunk in util_funcs.chunk(list(to_fetch), 20):
                await self._profile_handler.aget_profiles(c_chunk)
            self._since = util_funcs.date_as_ticks(datetime.now())
            self._my_task = None

        # now start a job to fetch those we don't have
        if self._my_task is None:
            self._my_task = asyncio.create_task(do_fetches())


async def init_user(user:Keys, profile_handler) -> Profile:
    ret: Profile = await profile_handler.get_profile(user.public_key_hex(),
                                                    create_missing=True)
    await aioconsole.aprint('running as - %s' % ret.display_name())
    await profile_handler.load_contacts(ret)

    # init contacts for those we follow too
    asyncio.create_task(profile_handler._fetch_contacts(ret.contacts.follow_keys()))

    return ret


async def do_search():
    try:
        args = get_args()
    except ConfigurationError as ce:
        print(ce)
        sys.exit(2)

    relay = args.relay.split(',')
    profile_store = MemoryProfileStore()
    # we'll look at events since here and onwards as we run to get pub_ks
    # you probably don't want to do many as it could be a lot of events
    since = util_funcs.date_as_ticks(datetime.now() - timedelta(minutes=args.since))
    as_user: Profile = None
    sub_id = None

    def do_sub():
        nonlocal sub_id
        filters = [{
            'kinds': [Event.KIND_META, Event.KIND_CONTACT_LIST,
                      Event.KIND_TEXT_NOTE, Event.KIND_CHANNEL_MESSAGE],
            'since': my_handler.since
        }]

        sub_id = my_client.subscribe(
            sub_id=sub_id,
            handlers=[
                my_handler
            ],
            filters=filters)

    def on_connect(the_client: Client):
        print('connect!!!??!?!?!?')
        do_sub()

    # def my_eose(the_client: Client, sub_id: str, events: [Event]):
    #     # add eose because it means these well get done in batch
    #     my_handler.do_event(the_client, sub_id, events)
    #     print('initial events loaded...')

    async def do_command(cmd: str):
        cmd_split = cmd.split()
        cmd = cmd_split[0]
        args = cmd_split[1:]
        output_formats = ('long', 'json', 'short')

        async def _show_profile():
            if output not in output_formats:
                await aioconsole.aprint('invalid output format %s - valid values %s' % (output,
                                                                                        output_formats))
                return

            if args:
                to_show = []
                for c_a in args[0].split(','):
                    k = Keys.get_key(c_a)
                    if k is None:
                        await aioconsole.aprint('%s is not a valid nostr key' % c_a)
                    else:
                        to_show.append(k)
                p: Profile
                for c_k in to_show:
                    p = await peh.get_profile(c_k.public_key_hex())
                    if p:
                        await display_profile(p,
                                              output=output,
                                              profile_handler=peh,
                                              as_user=as_user)
                    else:
                        await aioconsole.aprint('profile not found for key - %s' % c_k.public_key_bech32())

            else:
                await aioconsole.aprint('no keys supplied')

        if cmd == 'count':
            await aioconsole.aprint('%s profiles in store' % len(profile_store.select_profiles()))
        elif cmd == 'profile':
            output = 'long'
            if len(args) > 1:
                output = args[1]
            await _show_profile()
        elif cmd == 'contacts':
            output = 'short'
            for_user = as_user
            if len(args) == 1:
                k = Keys.get_key(args[0])
                if k:
                    for_user = await peh.aget_profile(k.public_key_hex())
                else:
                    output = args[0]
            elif len(args) == 2:
                k = Keys.get_key(args[0])
                if k:
                    for_user = await peh.aget_profile(k.public_key_hex())
                output = args[1]
            if for_user:
                if not for_user.contacts_is_set():
                    await peh.aload_contacts(for_user)
                c_contact: Contact
                await peh.aget_profiles([c_contact.contact_public_key for c_contact in for_user.contacts],
                                        create_missing=True)
                for c_contact in for_user.contacts:
                    c_p = await peh.aget_profile(c_contact.contact_public_key)
                    await display_profile(c_p,
                                          profile_handler=peh,
                                          as_user=as_user,
                                          output=output)
            else:
                await aioconsole.aprint('unable to get for_user for contacts')
        elif cmd == 'posts':
            for_user = as_user
            if args:
                k = Keys.get_key(args[0])
                if k:
                    for_user = await peh.aget_profile(k.public_key_hex())
            if for_user:
                events = await my_client.query({
                    'authors': [for_user.public_key],
                    'kinds': [Event.KIND_TEXT_NOTE],
                    'limit': 10
                })
                c_evt: Event
                for c_evt in events:
                    await post_printer.aprint_event(the_client=None,
                                                    sub_id=None,
                                                    evt=c_evt)
                    # await aioconsole.aprint('%s@%s' % (util_funcs.str_tails(c_evt.id), c_evt.created_at))
                    # await aioconsole.aprint(c_evt.content)
            else:
                await aioconsole.aprint('unable to get for_user for post')

        else:
            await aioconsole.aprint('unknown command - %s' % cmd)

    # start the client
    my_client = ClientPool(relay)
    asyncio.create_task(my_client.run())
    await my_client.wait_connect(timeout=10)
    peh = NetworkedProfileEventHandler(client=my_client,
                                       store=profile_store)
    my_handler = My_EventHandler(
        profile_handler=peh,
        since=since
    )

    # do as_user and boot user lookups before subscribing
    boot_pubs = []
    if args.as_user:
        boot_pubs.append(args.as_user.public_key_hex())
    if args.bootstrap:
        boot_pubs = boot_pubs + [k.public_key_hex() for k in args.bookeys]

    # actually fetch
    await my_client.query({
        'kinds': [Event.KIND_CONTACT_LIST, Event.KIND_META],
        'authors': boot_pubs
        },
        do_event=my_handler.do_event
    )

    if args.as_user:
        as_user = await init_user(args.as_user,
                                  peh)

    # used by $posts
    post_printer = FormattedEventPrinter(profile_handler=peh,
                                         as_user=as_user)
    # now add
    my_client.set_on_connect(on_connect)
    do_sub()

    msg = ''
    c_m: Profile
    while msg != 'exit':
        msg = await aioconsole.ainput('> ')
        msg = msg.lower()
        if msg.replace(' ','') == 'exit':
            continue
        elif msg and msg[0] == '$':
            await do_command(msg[1:])
        else:
            search_filter = {}
            if msg:
                search_filter['name'] = msg
                if msg.startswith('npub') or msg.startswith('nsec'):
                    try:
                        search_filter['public_key'] = Keys.get_key(msg).public_key_hex()
                    except Exception as e:
                        logging.debug(f'bad pr partial key {msg}?')
                else:
                    search_filter['public_key'] = msg
                search_filter['about'] = msg

            matches = profile_store.select_profiles(search_filter)
            if matches:
                for c_m in matches:
                    await display_profile(c_m,
                                          profile_handler=peh,
                                          as_user=as_user)
            else:
                await aioconsole.aprint('no matches found!')


if __name__ == "__main__":
    util_funcs.create_work_dir(WORK_DIR)
    util_funcs.create_sqlite_store(DB)
    asyncio.run(do_search())

