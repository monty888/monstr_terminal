import logging
import asyncio
import sys

import aioconsole
import argparse
from datetime import datetime, timedelta
from monstr.util import util_funcs
from monstr.ident.persist import MemoryProfileStore
from monstr.ident.event_handlers import NetworkedProfileEventHandler
from monstr.ident.profile import Profile
from monstr.event.persist import ClientSQLiteEventStore
from monstr.ident.alias import ProfileFileAlias
from monstr.event.event_handlers import StoreEventHandler
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
DEFAULT_RELAY = 'wss://nostr-pub.wellorder.net'
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
    parser.add_argument('-a', '--as', action='store', default=None,dest='as_user',
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
    p: Profile
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
        for c_k in ret.bootstrap.split(','):
            k = Keys.get_key(c_k)
            if k is None:
                p = my_alias.get_profile(c_k)
                if p is None:
                    raise ConfigurationError('bootstrap - %s not nostr key and no matching alias' % c_k)
                k = p.keys
            boot_keys.append(k)

    return ret


async def display_profile(p: Profile, short_form=True, key_output='npub'):
    pub_key = p.keys.public_key_bech32()
    if key_output != 'npub':
        pub_key = p.keys.public_key_hex()

    if short_form:
        await aioconsole.aprint(p.display_name(False)[0:15].rjust(15), ' - ', pub_key)
    else:
        await aioconsole.aprint('***** %s ******' % p.display_name())
        await aioconsole.aprint('keys\n')
        await aioconsole.aprint('npub: %s' % p.keys.public_key_bech32())
        await aioconsole.aprint('hex:  %s' % p.public_key)
        if p.get_attr('about'):
            await aioconsole.aprint('\nabout\n')
            await aioconsole.aprint('%s' % p.get_attr('about'))
        await aioconsole.aprint('')
        if p.get_attr('picture'):
            await aioconsole.aprint('\npicture\n')
            await aioconsole.aprint('%s' % p.get_attr('picture'))
        if p.get_attr('banner'):
            await aioconsole.aprint('\nbanner\n')
            await aioconsole.aprint('%s' % p.get_attr('banner'))


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
                await self._profile_handler.get_profiles(c_chunk)
            self._since = util_funcs.date_as_ticks(datetime.now())
            self._my_task = None

        # now start a job to fetch those we don't have
        if self._my_task is None:
            self._my_task = asyncio.create_task(do_fetches())


async def do_time_back_fill():
    pass


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
    as_user = None
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
        do_sub()

    # def my_eose(the_client: Client, sub_id: str, events: [Event]):
    #     # add eose because it means these well get done in batch
    #     my_handler.do_event(the_client, sub_id, events)
    #     print('initial events loaded...')

    async def do_command(cmd: str):
        if cmd in ('count'):
            if cmd == 'count':
                print('%s profiles in store' % len(profile_store.select_profiles()))
        else:
            aioconsole.aprint('unknown command - %s' % cmd)

    # start the client
    my_client = ClientPool(relay)
    asyncio.create_task(my_client.start())
    peh = NetworkedProfileEventHandler(client=my_client,
                                       store=profile_store)
    my_handler = My_EventHandler(
        profile_handler=peh,
        since=since
    )

    # do as_user and boot user lookups before subscribing
    boot_pubs = []
    if 'as_user' in args:
        boot_pubs.append(args.as_user.public_key_hex())
    if 'boot_keys' in args:
        boot_pubs = boot_pubs + [k.public_key_hex() for k in args.bookeys]
    # actually fetch
    await peh.get_profiles(boot_pubs)
    # now add
    my_client.set_on_connect(on_connect)
    do_sub()

    msg = ''
    c_m: Profile
    while msg != 'exit':
        msg = await aioconsole.ainput('> ')
        msg = msg.lower()
        cmd = msg.replace(' ', '')
        if cmd == 'exit':
            continue
        elif cmd and cmd[0] == '$':
            await do_command(cmd[1:])
        else:
            search_filter = {}
            if msg:
                search_filter['name'] = msg
                search_filter['public_key'] = msg
                search_filter['about'] = msg

            matches = profile_store.select_profiles(search_filter)
            if matches:
                for c_m in matches:
                    await display_profile(c_m)
            else:
                await aioconsole.aprint('no matches found!')


if __name__ == "__main__":
    util_funcs.create_work_dir(WORK_DIR)
    util_funcs.create_sqlite_store(DB)
    asyncio.run(do_search())

