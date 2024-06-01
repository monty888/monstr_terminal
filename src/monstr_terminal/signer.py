import logging
import asyncio
import aioconsole
import sys
import signal
import argparse
from pathlib import Path
from monstr.ident.alias import ProfileFileAlias
from monstr.encrypt import Keys
from monstr_terminal.util import load_toml, get_keys_from_str
from monstr.util import ConfigError
from monstr.signing.signing import BasicKeySigner
from monstr.signing.nip46 import NIP46ServerConnection

# work dir, we'll try and create if it doesn't exist
WORK_DIR = f'{Path.home()}/.nostrpy/'
# a toml file to get args from, can be overridden from cmd line
CONFIG_FILE = WORK_DIR + 'signer.toml'

# from relays and as_user the connect str is created
# e.g. bunker://AS_USER_HEX_PUB?relay=RELAY1&RELAY2 etc
# the other way is to get a connection str from a client TODO when find an example
# relay/s to attach to when bunker style remote connect
RELAYS = 'ws://localhost:8081'
# user to sign as when using remote style connect
AS_USER = None


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
    parser.add_argument('-r', '--relay', action='store', default=args['relay'],
                        help=f'comma separated nostr relays to connect to, default[{args["relay"]}]')
    parser.add_argument('-a', '--as-user', action='store', default=args['as_user'],
                        help=f"""
                        alias, priv_k or pub_k of user to view as. If only created from pub_k then kind 4
                        encrypted events will be left encrypted, 
                        default[{args['as_user']}]""")
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

    if not ret['as_user']:
        print('Required argument relay is missing. Use -a or --as_user')
        exit(1)

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
        alias_map = ProfileFileAlias(f'{WORK_DIR}profiles.csv')

        as_user = get_keys_from_str(keys=args['as_user'],
                                    private_only=True,
                                    alias_map=alias_map)[0]

        relays = args['relay'].split(',')

        # print out the information needed to connect
        print(f'connect with: {make_connect_str(as_user, relays)}')

        my_sign_con = NIP46ServerConnection(signer=BasicKeySigner(key=as_user),
                                            comm_k=None,
                                            relay=relays[0])

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
    logging.getLogger().setLevel(logging.ERROR)
    try:
        asyncio.run(main(get_args()))
    except ConfigError as ce:
        print(ce)






