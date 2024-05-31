import logging
import asyncio
from json import JSONDecodeError

import aioconsole
import sys
import signal
import json
import time
from pathlib import Path
from urllib.parse import urlparse,parse_qs
from monstr.client.client import Client
from monstr.client.event_handlers import EventHandler, DeduplicateAcceptor
from monstr.event.event import Event
from monstr.signing import BasicKeySigner, SignerInterface
from monstr.ident.alias import ProfileFileAlias
from monstr.util import util_funcs
from monstr.encrypt import Keys

WORK_DIR = f'{Path.home()}/.nostrpy/'

NIP46_KIND = 24133


def get_args():
    return {}


class SignerException(Exception):
    pass


class SignerConnection(EventHandler):

    def __init__(self,
                 signer: SignerInterface,
                 relay: str,
                 comm_k: str = None):

        self._signer = signer
        self._comm_k = comm_k
        self._relay = relay
        self._run = True

        # TODO - make client so that if it gets async for _on_connect, _do_event
        # it'll automaticlly create as task
        def _on_connect(my_client: Client):
            asyncio.create_task(_aon_connect(my_client))

        async def _aon_connect(my_client:Client):
            my_client.subscribe(
                handlers=[self],
                filters={
                    '#p': [await self._signer.get_public_key()],
                    'kinds': [NIP46_KIND]
                }
            )

        self._client = Client(self._relay, on_connect=_on_connect)

        # events queued and dealt with serially as they come in
        self._event_q: asyncio.Queue = asyncio.Queue()
        # start a process to work on the queued events
        self._event_process_task = asyncio.create_task(self._my_event_consumer())

        asyncio.create_task(self._client.run())

        super().__init__(event_acceptors=[
            DeduplicateAcceptor()
        ])

    async def describe(self):
        await self._client.wait_connect()
        sign_k = await self._signer.get_public_key()

        content = json.dumps({
            'id': 'somerndstring',
            'result': ['describe',
                       'get_public_key',
                       'sign_event',
                       'nip04_encrypt',
                       'nip04_decrypt',
                       'connect'],
            'error': None
        })

        content = await self._signer.nip4_encrypt(content, to_pub_k=self._comm_k)

        con_event = Event(pub_key=sign_k,
                          kind=NIP46_KIND,
                          content=content,
                          tags=[
                              ['p', self._comm_k]
                          ]
                          )

        await self._signer.sign_event(con_event)

        self._client.publish(con_event)

    async def _get_msg_event(self, content: str) -> Event:
        # returns encrypted and signed method for content

        # encrypt the content
        content = await self._signer.nip4_encrypt(content,
                                                  to_pub_k=self._comm_k)
        # make the event
        ret = Event(pub_key=await self._signer.get_public_key(),
                    kind=NIP46_KIND,
                    content=content,
                    tags=[
                        ['p', self._comm_k]
                    ]
                )
        # and sign it
        await self._signer.sign_event(ret)

        return ret

    async def _do_response(self, result: str = None, error: str = None, id: str = None):
        if result is None:
            result = ''
        if error is None:
            error = ''
        if id is None:
            id = util_funcs.get_rnd_hex_str(8)

        evt = await self._get_msg_event(json.dumps({
            'id': id,
            'result': result,
            'error': error
        }))

        self._client.publish(evt)

    async def _do_command(self, method: str, params: [str]):
        id = util_funcs.get_rnd_hex_str(8)

        evt = await self._get_msg_event(json.dumps({
            'id': id,
            'method': method,
            'params': params
        }))

        self._client.publish(evt)
        return id

    async def request_connect(self):
        await self._do_command('connect', [await self._signer.get_public_key()])

    # async def do_ack(self):
    #     await self._do_response(result=)

    async def connect(self, id: str, params: [str]):
        if self._comm_k is None:
            self._comm_k = params[0]

        await self._do_response(result=await self._signer.get_public_key(),
                                id=id)

    # async def describe(self, id: str, params: [str]):
    #     await self._do_response(result=['describe',
    #                                     'get_public_key',
    #                                     'sign_event',
    #                                     'nip04_decrypt',
    #                                     'connect'],
    #                             id=id)

    async def get_public_key(self, id: str, params: [str]):
        await self._do_response(result=await self._signer.get_public_key(),
                                id=id)

    async def nip04_encrypt(self, id: str, params: [str]):
        try:
            n_params = len(params)
            if n_params < 2:
                raise SignerException(
                    f'Signer::nip04_encrypt: requires 2 params got {n_params} - from key and ciper text')

            to_k = params[0]
            plain_text = params[1]
            if not Keys.is_hex_key(to_k):
                raise SignerException(
                    f'Signer::nip04_encrypt: from key is not valid {to_k}')

            ciper_text = await self._signer.nip4_encrypt(plain_text=plain_text,
                                                         to_pub_k=to_k)

            await self._do_response(result=ciper_text,
                                    id=id)

        except SignerException as se:
            await self._do_response(error=str(se),
                                    id=id)
        except Exception as e:
            await self._do_response(error=f'Signer::nip04_encrypt:'
                                          f'unable to decrypt as {await self._signer.get_public_key()}'
                                          f' error - {str(e)}',
                                    id=id)

    async def nip04_decrypt(self, id: str, params: [str]):
        try:
            n_params = len(params)
            if n_params < 2:
                raise SignerException(
                    f'Signer::nip04_decrypt: requires 2 params got {n_params} - from key and ciper text')

            from_k = params[0]
            payload = params[1]
            if not Keys.is_hex_key(from_k):
                raise SignerException(
                    f'Signer::nip04_decrypt: from key is not valid {from_k}')

            plain_text = await self._signer.nip4_decrypt(payload=payload,
                                                   for_pub_k=from_k)

            await self._do_response(result=plain_text,
                                    id=id)

        except SignerException as se:
            await self._do_response(error=str(se),
                                    id=id)
        except Exception as e:
            await self._do_response(error=f'Signer::nip04_decrypt:'
                                          f'unable to decrypt as {await self._signer.get_public_key()}'
                                          f' error - {str(e)}',
                                    id=id)

    async def sign_event(self, id: str, params: [str]):
        try:
            evt_data = json.loads(params[0])
            event = Event.load(evt_data)

            await self._signer.sign_event(event)
            await self._do_response(result=json.dumps(event.data()),
                                    id=id)

        except JSONDecodeError as je:
            await self._do_response(error=f'Signer::sign_event: bad event JSON - {je}',
                                    id=id)
        except Exception as e:
            await self._do_response(error=f'Signer::sign_event: {e}',
                                    id=id)




    async def _my_event_consumer(self):
        while self._run:
            try:
                args = await self._event_q.get()
                await self.ado_event(*args)

            except Exception as e:
                print(e)

    def do_event(self, the_client: Client, sub_id, evt: Event):
        if not self.accept_event(the_client=the_client,
                                 sub_id=sub_id,
                                 evt=evt):
            return
        # put events on a queue so we can deal with async
        self._event_q.put_nowait(
            (the_client, sub_id, evt)
        )

    async def ado_event(self, the_client: Client, sub_id, evt: Event):
        decrypted_evt = await self._signer.nip4_decrypt_event(evt)

        try:
            cmd_dict = json.loads(decrypted_evt.content)
            if 'method' in cmd_dict:
                id = cmd_dict['id']
                method = cmd_dict['method']
                params = cmd_dict['params']

                if method in {'connect',
                              'describe',
                              'get_public_key',
                              'nip04_decrypt',
                              'nip04_encrypt',
                              'sign_event'}:

                    await getattr(self, method)(id, params)

        except Exception as e:
            print(e)
            logging.debug(f'SignerConnection::ado_event {e}')

        print('ado event', decrypted_evt.data())

    def end(self):
        self._run = False
        self._client.end()


async def main(args):
    try:
        con_str = await aioconsole.ainput('connection string: ')
        parsed = urlparse(con_str)

        query_args = parse_qs(parsed.query)
        comm_k = None
        if parsed.scheme == 'nostrconnect':
            comm_k = parsed.netloc

        relay = query_args['relay'][0]

        print(f'comm pub_k: {comm_k}')
        print(f'using relay: {relay}')

        my_alias = ProfileFileAlias(f'{WORK_DIR}profiles.csv')
        use_profile = my_alias.get_profile('monty')

        my_sign_con = SignerConnection(signer=BasicKeySigner(key=use_profile.keys),
                                       comm_k=None,
                                       relay=relay)

        def sigint_handler(signal, frame):
            my_sign_con.end()
            sys.exit(0)

        signal.signal(signal.SIGINT, sigint_handler)

        if comm_k is not None:
            await my_sign_con.request_connect()

        while True:
            await asyncio.sleep(0.1)

    except Exception as e:
        print(e)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(main(get_args()))





