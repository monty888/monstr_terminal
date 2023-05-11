"""
watches one relay and post what it sees into another
"""
import logging
import asyncio
from datetime import datetime,timedelta
from monstr.util import util_funcs
from monstr.client.client import Client, ClientPool
from monstr.client.event_handlers import RepostEventHandler


async def do_mirror(from_url,
                    to_url,
                    base_filter=None,
                    as_users=None,
                    since=datetime.now()):

    def get_filter():
        ret = base_filter
        if as_users:
            # here we should fetch contacts of as_users and add all returned pubks to authors in filter
            pass

        return ret

    async with ClientPool(from_url) as from_relay:
        print('connected to from relay')
        use_filter = get_filter()


        # now start mirroring to to_url
        async with ClientPool(to_url) as to_relay:
            print('mirroring from %s to %s with filter %s' % (from_url,
                                                              to_url,
                                                              use_filter))
            my_repost = RepostEventHandler(to_relay)

            def on_connect(the_from_relay):
                the_from_relay.subscribe('my_mirror',
                                         handlers=my_repost,
                                         filters=use_filter)

            # manually call to make the sub
            on_connect(from_relay)

            while True:
                await asyncio.sleep(0.5)


    # # where we're posting to
    # to_relay = ClientPool(to_relay)
    # asyncio.create_task(to_relay.run())
    #
    # # TODO add EOSE support
    # my_repost = RepostEventHandler(to_relay)
    # def on_connect(the_from_relay):
    #     the_from_relay.subscribe(handlers=my_repost, filters=get_filter())
    #
    # from_relay = ClientPool(from_relay, on_connect=on_connect)
    # await from_relay.run()
    #
    # print('starting mirror \nfrom %s to %s \nwith filter=%s' % (from_relay, to_relay, filter))

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)

    # from_relay = ['ws://localhost:8082/','ws://localhost:8083/']
    from_relay = ['wss://nos.lol']
    to_relay = ['ws://localhost:8081/']
    # events will be fetch from this time point, default now
    since = None
    if since is None:
        since = util_funcs.date_as_ticks(datetime.now())

    # base filter for example to only mirror set kinds
    # {kinds: [Event.KIND..., ]}
    base_filter = {
        'since': since
    }

    # if given the kind 3 for this keys will be looked up and
    # the base query will be modified to request from aithors
    # mentioned in the returned contacts, default any
    as_user = None

    asyncio.run(do_mirror(from_relay, to_relay,
                          base_filter=base_filter))
