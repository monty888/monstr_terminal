import logging
import asyncio
import aioconsole
import argparse
from datetime import datetime, timedelta
from monstr.util import util_funcs
from monstr.ident.persist import MemoryProfileStore
from monstr.ident.event_handlers import NetworkedProfileEventHandler
from monstr.ident.profile import Profile
from monstr.event.persist import ClientSQLiteEventStore
from monstr.event.event_handlers import StoreEventHandler
from monstr.client.event_handlers import EventHandler
from monstr.client.client import ClientPool, Client
from monstr.event.event import Event
from pathlib import Path

# defaults if not otherwise given
# working directory it'll be created it it doesn't exist
WORK_DIR = '%s/.nostrpy/' % Path.home()
# relay/s to attach to
DEFAULT_RELAY = 'wss://nostr-pub.wellorder.net'
# profiles persited here sqlite db
DB = WORK_DIR + 'monstr.db'
# how far to fetch metas back too in days
DEFAULT_SINCE = 1


def get_args():
    parser = argparse.ArgumentParser(
        prog='profile_search.py',
        description='search for nostr user profiles'
    )
    parser.add_argument('-r', '--relay', action='store', default=DEFAULT_RELAY,
                        help='comma separated urls of relays to connect to - default %s' % DEFAULT_RELAY)
    parser.add_argument('-s', '--since', action='store', default=90, type=int,
                        help='n days to search back for profile events - default %s' % DEFAULT_SINCE)
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')

    ret = parser.parse_args()

    if ret.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    return ret


async def display_profile(p: Profile, short_form=True, key_output='npub'):
    pub_key = p.keys.public_key_bech32()
    if key_output != 'npub':
        pub_key = p.keys.public_key_hex()

    if short_form:
        await aioconsole.aprint(p.display_name(False)[0:10].rjust(10), ' - ', pub_key)
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

        # if meta update now
        self._profile_handler.do_event(client, sub_id, Event.latest_events_only(evt))

        # for all other events extract pub_k and p_tag
        c_evt: Event
        other_events = [c_evt for c_evt in evt if c_evt.kind != Event.KIND_META]

        u_pubs = set()
        for c_evt in other_events:
            # print('get us')
            u_pubs.add(c_evt.pub_key)
            for pub_k in c_evt.p_tags:
                u_pubs.add(pub_k)

        async def do_fetches():
            for c_chunk in util_funcs.chunk(list(u_pubs), 20):
                await self._profile_handler.get_profiles(c_chunk)
            self._since = util_funcs.date_as_ticks(datetime.now())

        # now start a job to fetch those we don't have
        asyncio.create_task(do_fetches())


async def do_time_back_fill():
    pass


async def do_search():
    args = get_args()
    relay = args.relay.split(',')
    profile_store = MemoryProfileStore()
    # we'll look at events since here and onwards as we run to get pub_ks
    since = util_funcs.date_as_ticks(datetime.now() - timedelta(minutes=10))

    def on_connect(the_client: Client):
        # add a sub to pick up metas for ongoing events
        my_client.subscribe(
            handlers=[
                my_handler
            ],
            filters={
                'kinds': [Event.KIND_META, Event.KIND_CONTACT_LIST, Event.KIND_TEXT_NOTE],
                'since': util_funcs.date_as_ticks(datetime.now())
            })

    def my_eose(the_client: Client, sub_id: str, events: [Event]):
        # add eose because it means these well get done in batch
        my_handler.do_event(the_client, sub_id, events)
        print('initial events loaded...')

    async def do_command(cmd: str):
        if cmd in ('count'):
            if cmd=='count':
                print('%s profiles in store' % len(profile_store.select_profiles()))
        else:
            aioconsole.aprint('unknown command - %s' % cmd)

    my_client = ClientPool(relay,
                           on_connect=on_connect,
                           on_eose=my_eose)
    peh = NetworkedProfileEventHandler(client=my_client,
                                       store=profile_store)
    my_handler = My_EventHandler(
        profile_handler=peh,
        since=since
    )

    asyncio.create_task(my_client.start())

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

