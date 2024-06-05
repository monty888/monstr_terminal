import datetime
import logging
import asyncio
import aioconsole
import sys
import signal
import argparse
from pathlib import Path
from monstr.encrypt import Keys
from monstr_terminal.util import load_toml, get_keys_from_str, get_sqlite_key_store
from monstr.util import ConfigError
from monstr.signing.signing import BasicKeySigner
from monstr.signing.nip46 import NIP46ServerConnection, NIP46AuthoriseInterface

# work dir, we'll try and create if it doesn't exist
WORK_DIR = f'{Path.home()}/.nostrpy/'
# a toml file to get args from, can be overridden from cmd line
CONFIG_FILE = WORK_DIR + 'signer.toml'
# filename for key store
KEY_STORE_DB_FILE = 'keystore.db'

# from relays and as_user the connect str is created
# e.g. bunker://AS_USER_HEX_PUB?relay=RELAY1&RELAY2 etc
# the other way is to get a connection str from a client TODO when find an example
# relay/s to attach to when bunker style remote connect
RELAYS = 'ws://localhost:8081'
# user to sign as when using remote style connect
AS_USER = None


class BooleanAuthorise(NIP46AuthoriseInterface):

    async def authorise(self, method: str, id: str, params: [str]) -> bool:
        print('method', method)
        print('params', params)
        accept = await aioconsole.ainput('authorise y/n? ')
        return accept.lower() == 'y'


class TimedAuthorise(BooleanAuthorise):

    def __init__(self, auth_mins = 10):
        self._last_auth_at = None
        self._auth_delta = datetime.timedelta(minutes=auth_mins)

    async def authorise(self, method: str, id: str, params: [str]) -> bool:
        now = datetime.datetime.now()
        ret = True

        # maybe we need to reauth?
        if self._last_auth_at is None or (now - self._last_auth_at) > self._auth_delta:
            ret = await super().authorise(method, id, params)
            if ret:
                self._last_auth_at = now

        return ret


def get_cmdline_args(args) -> dict:
    parser = argparse.ArgumentParser(
        prog='signer.py',
        description="""
            A NIP46 client
            """
    )
    parser.add_argument('-c', '--conf', action='store', default=args['conf'],
                        help=f'name com TOML file to use for configuration, default[{args["conf"]}]')
    parser.add_argument('--work-dir', action='store', default=args['work_dir'],
                        help=f'base dir for files used if full path isn\'t given, default[{args["work_dir"]}]')
    parser.add_argument('user', action='store', default=args['as_user'],
                        nargs='?',
                        help=f"""
                        alias, priv_k or pub_k of user to view as. If only created from pub_k then kind 4
                        encrypted events will be left encrypted,
                        default[{args['as_user']}]""")
    parser.add_argument('-r','--relay',
                        action='store',
                        default=args['relay'],
                        help=f'comma separated nostr relays to connect to, default[{args["relay"]}]')
    parser.add_argument('--auth', action='store', default=args['auth'],
                        help=f'action on receiving requests to perform signing operations '
                             f'all - always accept, ask - always ask or int value to ask every n minutes, default[{args["auth"]}]')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output', default=args['debug'])
    ret = parser.parse_args()
    return vars(ret)


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
        'auth': 'all',
        'debug': False
    }

    # only done to get the work-dir and conf options if set
    ret.update(get_cmdline_args(ret))
    # now form config file if any
    ret.update(load_toml(ret['conf'], ret['work_dir']))
    #
    # # 2pass so that cmdline options override conf file options
    # ret.update(get_cmdline_args(ret))

    # if debug flagged enable now
    if ret['debug'] is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(f'get_args:: running with options - {ret}')

    if not ret['relay']:
        print('Required argument relay is missing. Use -r or --relay')
        exit(1)

    # force get a user
    if not ret['as_user']:
        ret['as_user'] = input('as user: ')
        # print('Required argument relay is missing. Use -a or --as_user')
        # exit(1)

    auth = ret['auth'].lower()
    if auth not in ('all','ask'):
        try:
            ret['auth'] = int(auth)
        except ValueError:
            raise ConfigError(f'auth most be all, ask or interger value got - {auth}')

    return ret


def make_connect_str(as_user:Keys, relays: [str]):
    return f'bunker://{as_user.public_key_hex()}?relay={"&".join(relays)}'


async def main(args):
    """
        This is set to work where we create the connection string, there is another method where the client that
        wants us to sign creates the connection str and then we connct to that.
        Originally thats what we did and so I'm pretty sure changes to support that method would be pretty minor
        (I think it basically just changes who decides the comm key)
        Anyway this code works as a signer for
            https://nostrudel.ninja/
            sign in -> advanced -> nostr connect -> paste the string there we create

            test with other implementations as find them
    """
    try:
        # TODO: make a proper keymap store and store the keys encryted
        # with at least the option of using password to unencrypt
        key_store = get_sqlite_key_store(db_file=WORK_DIR+KEY_STORE_DB_FILE)

        as_user = (await get_keys_from_str(keys=args['as_user'],
                                           private_only=True,
                                           key_store=key_store))[0]

        relays = args['relay'].split(',')

        # create the authoriser if any, this decide how we ask user to proceed on requests for sign ops
        my_auth = None
        auth_type = args['auth']
        if auth_type == 'ask':
            print('all operations will require manual authorisation')
            my_auth = BooleanAuthorise()
        elif isinstance(auth_type, int):
            my_auth = TimedAuthorise(auth_mins=auth_type)
            print(f'operations will require manual authorisation every {auth_type} minutes')
        else:
            print(f'operations will always be authorised')

        # print out the information needed to connect
        print(f'connect with: {make_connect_str(as_user, relays)}')

        my_sign_con = NIP46ServerConnection(signer=BasicKeySigner(key=as_user),
                                            comm_k=None,
                                            relay=relays[0],
                                            authoriser=my_auth)

        def sigint_handler(signal, frame):
            my_sign_con.end()
            sys.exit(0)

        signal.signal(signal.SIGINT, sigint_handler)


        # this is for the other style of connection where the client choses the comm
        # if comm_k is not None:
        #     await my_sign_con.request_connect()

        while True:
            await asyncio.sleep(0.1)

    except Exception as e:
        print(e)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.INFO)
    try:
        asyncio.run(main(get_args()))
    except ConfigError as ce:
        print(ce)






