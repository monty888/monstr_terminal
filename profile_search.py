import logging
import asyncio
from datetime import datetime, timedelta
from monstr.util import util_funcs
from monstr.ident.persist import SQLiteProfileStore
from monstr.ident.event_handlers import NetworkedProfileEventHandler
from monstr.event.persist import ClientSQLiteEventStore
from monstr.event.event_handlers import EventHandler
from monstr.client.client import ClientPool, Client
from monstr.event.event import Event
from pathlib import Path

# defaults if not otherwise given
# working directory it'll be created it it doesn't exist
WORK_DIR = '%s/.nostrpy/' % Path.home()
# relay/s to attach to
RELAYS = ['wss://nostr-pub.wellorder.net']
# profiles persited here sqlite db
DB = WORK_DIR + 'monstr.db'


async def do_search():
    min_since = util_funcs.date_as_ticks(datetime.now() - timedelta(days=90))
    since = None
    profile_store = SQLiteProfileStore(DB)
    event_store = ClientSQLiteEventStore(DB)

    def on_connect(my_client: Client):
        nonlocal since
        if since is None:
            since = event_store.get_newest(my_client.url, filter={
                'kinds': Event.KIND_META
            })

        my_client.subscribe(
            handlers=[
                peh, eh
            ],filters={
                'kinds': [Event.KIND_META],
                'since': since
            })

        # update since so we don't fetch back in time if we have to reconnect
        since = util_funcs.date_as_ticks(datetime.now())

    my_client = ClientPool(RELAYS,
                           on_connect=on_connect)
    peh = NetworkedProfileEventHandler(client=my_client,
                                       store=profile_store)
    eh = EventHandler(store=event_store)

    await my_client.start()
    run = True
    while run == True:
        asyncio.sleep(0.1)



if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    util_funcs.create_work_dir(WORK_DIR)
    util_funcs.create_sqlite_store(DB)
    asyncio.run(do_search())