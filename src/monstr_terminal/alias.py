"""
usage: alias.py [-h] [-n] [-l] [-f FILENAME] [-k KEYS] profile_name

        link nostr keypairs to profile names

        alias.py <profile_name>           view existing mapping
        alias.py -n <profile_name>        map new keys auto generated
        alias.py -n <profile_name> <key>  map new with supplied key if pub_k then view only
        alias.py -l <profile_name> <key>  map existing to key, any exsting mapping overridden



positional arguments:
  profile_name          profile_name to perform action on

options:
  -h, --help            show this help message and exit
  -n, --new             create a new profile key pair link
  -l, --link            link key pair to exiting profile file, any existing mapping will be overridden
  -f FILENAME, --filename FILENAME
                        mappings in this file, default is {home}/profiles.csv
  -k KEYS, --keys KEYS  npub/nsec for the profile

"""
import logging
import asyncio
import sys
import argparse
from pathlib import Path
from monstr.util import ConfigError
from monstr.ident.keystore import NamedKeys, SQLiteKeyStore, KeystoreInterface
from monstr.encrypt import Keys, DecryptionException
from monstr_terminal.util import load_toml, get_sqlite_key_store

# defaults if not otherwise given
# working directory it'll be created it it doesn't exist
WORK_DIR = f'{Path.home()}/.nostrpy/'
# alias toml file
CONFIG_FILE = 'alias.toml'
# filename for key store
KEY_STORE_DB_FILE = 'keystore.db'

def print_k(k: NamedKeys, hex=True, bech32=True, include_private=True):
    print(k.name)
    if hex:
        print('** hex **')
        k.print_hex(include_private=include_private)
    if bech32:
        print('** bech32 **')
        k.print_bech32(include_private=include_private)


async def do_view(store: SQLiteKeyStore, name: str):
    k = await store.get(name)
    if k:
        print_k(k)
    else:
        print(f'profile not found: {name}')
    sys.exit(0)


async def do_delete(store: KeystoreInterface, name: str):
    if await store.get(name):
        yn = input(f'delete {name}, are you sure? ').lower()
        if yn == 'y':
            await store.delete(name)
            print(f'deleted {name}')
        else:
            print('not deleted')
    else:
        print(f'{name} not found to delete')
    sys.exit(0)


async def do_add(store: KeystoreInterface, name: str, keys: str):
    # new and generate keys
    if keys is None:
        keys = Keys()
    # new but keys supplied by user
    else:
        keys = Keys.get_key(keys)

    k = await store.add(k=keys,
                        name=name)

    print(f'created profile: {name}')
    print_k(k)


async def do_link(store: KeystoreInterface, name: str, keys: str):
    if keys is None:
        raise ConfigError('keys required to link')
    try:
        keys = Keys(keys)
        k = await store.update(k=keys,
                               name=name)

        print(f'linked keys to profile: {name}')
        print_k(k)
    except Exception as e:
        raise ConfigError(str(e))


async def do_list(store: KeystoreInterface):
    keys = await store.select()
    for k in keys:
        print(k)

def get_cmdline_args(args) -> dict:
    parser = argparse.ArgumentParser(description="""
            link nostr keypairs to profile names

            alias.py <profile_name>           view existing mapping
            alias.py -n <profile_name>        map new keys auto generated
            alias.py -n <profile_name> <key>  map new with supplied key if pub_k then view only
            alias.py -d <profile_name>        delete profile
            alias.py -l <profile_name> <key>  map existing to key, any exsting mapping overridden

        """, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-n', '--new',
                        help='create a new profile key pair link',
                        action='store_true')
    parser.add_argument('-l', '--link',
                        help='link key pair to exiting profile file, any existing mapping will be overridden',
                        action='store_true')
    parser.add_argument('-d', '--delete',
                        help='delete an existing profile',
                        action='store_true')
    parser.add_argument('-a', '--all',
                        help='lists all existing profiles',
                        action='store_true')
    parser.add_argument('-f', '--filename',
                        default=args['keystore']['filename'],
                        type=str,
                        help=f'mappings in this file, default [{args["keystore"]["filename"]}]')
    parser.add_argument('profile_name',
                        nargs='?',
                        type=str,
                        help='profile_name to perform action on')
    parser.add_argument('-k',
                        '--keys',
                        help='npub/nsec for the profile',
                        default=None)
    parser.add_argument('--debug', action='store_true', help='enable debug output', default=args['debug'])
    return vars(parser.parse_args())


def get_args() -> dict:
    """
    get args to use order is
        default -> toml_file -> cmd_line options

    so command line option is given priority if given

    :return: {}
    """

    ret = {
        'keystore': {
            'filename': WORK_DIR + KEY_STORE_DB_FILE,
            'password': None
        },
        'debug': False
    }

    # now form config file if any
    load_toml(dir=WORK_DIR,
              filename=CONFIG_FILE,
              current_args=ret)

    # now from cmd line
    ret.update(get_cmdline_args(ret))

    # if debug flagged enable now and output args we're running with
    if ret['debug'] is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(f'get_args:: running with options - {ret}')

    return ret


async def profile_creator():
    args = get_args()
    profile_name = args['profile_name']
    keys = args['keys']

    # the key store, with encryptor for keys
    key_store = get_sqlite_key_store(db_file=args['keystore']['filename'],
                                     password=args['keystore']['password'])

    op_count = sum([args['delete'], args['new'], args['link']])
    if op_count > 1:
        print('only one of --new, --link or --delete can be set')
        sys.exit(1)

    try:
        # must be view
        if args['all'] is True:
            if profile_name is True:
                print('profile name ignored with view --all')
            await do_list(key_store)
        else:
            # get profile name as we need it
            if profile_name is None:
                profile_name = input('name: ')

            # if op count is 0 then must be view profile name
            if op_count == 0:
                if profile_name:
                    await do_view(store=key_store,
                                  name=profile_name)
            # else one of the ops must be true
            elif args['delete']:
                await do_delete(store=key_store,
                                name=profile_name)
            elif args['new']:
                await do_add(store=key_store,
                             name=profile_name,
                             keys=keys)
            elif args['link']:
                await do_link(store=key_store,
                              name=profile_name,
                              keys=keys)
    except ConfigError as ce:
        print(ce)
    except DecryptionException as de:
        print(f'bad password or non encrypted store? - {de}')
    except Exception as e:
        print(e)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    logging.getLogger().setLevel(logging.ERROR)
    asyncio.run(profile_creator())





