import logging
import asyncio
import aioconsole
import sys
import signal
import json
from pathlib import Path
from urllib.parse import urlparse,parse_qs
from monstr.client.client import Client
from monstr.client.event_handlers import EventHandler
from monstr.event.event import Event
from monstr.signing import BasicKeySigner, SignerInterface
from monstr.ident.alias import ProfileFileAlias


WORK_DIR = f'{Path.home()}/.nostrpy/'

NIP46_KIND = 24133

def get_args():
    return {}


class SignerConnection(EventHandler):

    def __init__(self,
                 signer: SignerInterface,
                 comm_k: str,
                 relay: str):

        self._signer = signer
        self._comm_k = comm_k
        self._relay = relay

        def _on_connect(my_client: Client):
            my_client.subscribe(
                handlers=[self],
                filters={
                    'kinds': [NIP46_KIND]
                }
            )

        self._client = Client(self._relay, on_connect=_on_connect)

        asyncio.create_task(self._client.run())

    async def describe(self):
        await self._client.wait_connect()
        sign_k = await self._signer.get_public_key()

        content = json.dumps({
            'id': 'somerndstring',
            'result': ['describe', 'get_public_key', 'sign_event', 'connect'],
            'error': None
        })

        content = await self._signer.encrypt_text(content, to_pub_k=self._comm_k)

        con_event = Event(pub_key=sign_k,
                          kind=NIP46_KIND,
                          content=content,
                          tags=[
                              ['p', self._comm_k]
                          ]
                          )

        await self._signer.sign_event(con_event)

        self._client.publish(con_event)


    async def connect(self):
        await self._client.wait_connect()
        sign_k = await self._signer.get_public_key()

        content = json.dumps({
            'id': 'somerndstring',
            'method': 'connect',
            'params': [sign_k]
        })

        content = await self._signer.encrypt_text(content, to_pub_k=self._comm_k)

        con_event = Event(pub_key=sign_k,
                          kind=NIP46_KIND,
                          content=content,
                          tags=[
                              ['p', self._comm_k],
                              ['p', sign_k]
                          ]
                          )

        await self._signer.sign_event(con_event)

        self._client.publish(con_event)

    def do_event(self, the_client: Client, sub_id, evt: Event):
        print('seen event')
        print(evt.event_data())

    def __del__(self):
        pass
        # self._client.end()


async def main(args):
    try:
        con_str = await aioconsole.ainput('connection string: ')
        parsed = urlparse(con_str)
        query_args = parse_qs(parsed.query)

        print(query_args)

        comm_k = parsed.netloc
        relay = query_args['relay'][0]

        print(f'comm pub_k: {comm_k}')
        print(f'using relay: {relay}')

        my_alias = ProfileFileAlias(f'{WORK_DIR}profiles.csv')
        use_profile = my_alias.get_profile('monty_test')

        my_sign_con = SignerConnection(signer=BasicKeySigner(key=use_profile.keys),
                                       comm_k=comm_k,
                                       relay=relay)

        def sigint_handler(signal, frame):
            sys.exit(0)

        signal.signal(signal.SIGINT, sigint_handler)

        await my_sign_con.connect()

        while True:
            await asyncio.sleep(0.1)

    except Exception as e:
        print(e)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)
    asyncio.run(main(get_args()))

