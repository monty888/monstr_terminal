import datetime
import logging
import asyncio
import aioconsole
import sys
import signal
import argparse
from pathlib import Path
from monstr.encrypt import DecryptionException
from monstr_terminal.util import load_toml, get_sqlite_key_store, get_signer_from_str
from monstr.util import ConfigError
from monstr.signing.nip46 import NIP46ServerConnection, AuthoriseAll, RequestAuthorise, TimedAuthorise

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
USER = None
# print info on each event we get request to sign
VERBOSE = False


async def print_auth_info(method:str, id: str, params:dict):
    print('method', method)
    print('params', params)

async def request_auth(method:str, id: str, params:dict) -> bool:
    accept = await aioconsole.ainput('authorise y/n? ')
    return accept.lower() == 'y'

# class AuthoriseAll(NIP46AuthoriseInterface):
#
#     def __init__(self, verbose: bool = False):
#         self._verbose = verbose
#
#     async def authorise(self, method: str, id: str, params: [str]) -> bool:
#         if self._verbose:
#             print_auth_info(method, params)
#         return True
#
#
# class BooleanAuthorise(NIP46AuthoriseInterface):
#
#     async def authorise(self, method: str, id: str, params: [str]) -> bool:
#         # always verbose
#         print_auth_info(method, params)
#         accept = await aioconsole.ainput('authorise y/n? ')
#         return accept.lower() == 'y'
#
#
# class TimedAuthorise(BooleanAuthorise):
#
#     def __init__(self, auth_mins = 10, verbose: bool = False):
#         self._last_auth_at = None
#         self._auth_delta = datetime.timedelta(minutes=auth_mins)
#         self._verbose = verbose
#
#     async def authorise(self, method: str, id: str, params: [str]) -> bool:
#         if self._verbose:
#             print_auth_info(method, params)
#         now = datetime.datetime.now()
#         ret = True
#
#         # maybe we need to reauth?
#         if self._last_auth_at is None or (now - self._last_auth_at) > self._auth_delta:
#             ret = await super().authorise(method, id, params)
#             if ret:
#                 self._last_auth_at = now
#
#         return ret


def get_cmdline_args(args) -> dict:
    parser = argparse.ArgumentParser(
        prog='signer.py',
        description="""
            A NIP46 server - signs events on behalf of another client
            """
    )
    parser.add_argument('-c', '--conf', action='store', default=args['conf'],
                        help=f'name com TOML file to use for configuration, default[{args["conf"]}]')
    parser.add_argument('--work-dir', action='store', default=args['work_dir'],
                        help=f'base dir for files used if full path isn\'t given, default[{args["work_dir"]}]')
    parser.add_argument('user', action='store', default=args['user'],
                        nargs='?',
                        help=f"""
                        alias or priv_k that we are signing as
                        default[{args['user']}]""")
    parser.add_argument('-r', '--relay',
                        action='store',
                        default=args['relay'],
                        help=f'comma separated nostr relays to connect to, default[{args["relay"]}]')
    parser.add_argument('-a', '--auth',
                        action='store',
                        default=args['auth'],
                        help=f'action on receiving requests to perform signing operations '
                             f'all - always accept, ask - always ask or int value to ask every n minutes, default[{args["auth"]}]')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help=f'print info on each event that is requested to sign, default[{args["verbose"]}]',
                        default=args['verbose'])
    parser.add_argument('--no-verbose',
                        action='store_false',
                        help='turn off verbose',
                        default=not args['verbose'])
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
        'user': USER,
        'auth': 'all',
        'verbose': VERBOSE,
        'debug': False,
        'keystore': {
            'filename': WORK_DIR + KEY_STORE_DB_FILE,
            'password': None
        }
    }

    # only done to get the work-dir and conf options if set
    ret.update(get_cmdline_args(ret))
    # now form config file if any
    load_toml(filename=ret['conf'],
              dir=ret['work_dir'],
              current_args=ret)
    # # 2pass so that cmdline options override conf file options
    ret.update(get_cmdline_args(ret))

    # if debug flagged enable now
    if ret['debug'] is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(f'get_args:: running with options - {ret}')

    if not ret['relay']:
        print('Required argument relay is missing. Use -r or --relay')
        exit(1)

    # force get a user
    if not ret['user'] or ret['user'] == '?':
        ret['user'] = input('as user: ')

    auth = ret['auth'].lower()
    if auth not in ('all', 'ask'):
        try:
            ret['auth'] = int(auth)
        except ValueError:
            raise ConfigError(f'auth most be all, ask or integer value got - {auth}')

    return ret


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
        # store of aliases to keys
        key_store = get_sqlite_key_store(db_file=args['keystore']['filename'],
                                         password=args['keystore']['password'])

        # user we're signing for
        user_sign = await get_signer_from_str(key=args['user'],
                                              key_store=key_store)

        # relays to attach to
        relays = args['relay'].split(',')

        # print info about events as we auth
        verbose = args['verbose']
        auth_info = None
        if verbose:
            auth_info = print_auth_info


        # create the authoriser if any, this decide how we ask user to proceed on requests for sign ops
        auth_type = args['auth']

        if auth_type == 'ask':
            print('all operations will require manual authorisation')
            my_auth = RequestAuthorise(auth_info=auth_info,
                                       request_auth=request_auth)
        elif isinstance(auth_type, int):
            my_auth = TimedAuthorise(auth_mins=auth_type,
                                     request_auth=request_auth,
                                     auth_info=auth_info)
            print(f'operations will require manual authorisation every {auth_type} minutes')
        else:
            my_auth = AuthoriseAll(auth_info=auth_info)
            print(f'operations will always be authorised')

        my_sign_con = NIP46ServerConnection(signer=user_sign,
                                            relay=relays,
                                            authoriser=my_auth)

        # print out the information needed to connect
        print(f'connect with: {await my_sign_con.bunker_url}')

        def sigint_handler(signal, frame):
            my_sign_con.end()
            sys.exit(0)

        signal.signal(signal.SIGINT, sigint_handler)

        # this is for the other style of connection where the client chooses the comm
        # snort used to have this style, add back in if we can find an example to test against
        # if comm_k is not None:
        #     await my_sign_con.request_connect()

        await my_sign_con.run()

    except ConfigError as ce:
        print(ce)
    except DecryptionException as de:
        print(f'bad password or non encrypted store? - {de}')
    except Exception as e:
        print(e)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)
    try:
        asyncio.run(main(get_args()))
    except ConfigError as ce:
        print(ce)






