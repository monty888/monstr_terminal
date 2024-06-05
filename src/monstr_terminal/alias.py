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
from getpass import getpass
from pathlib import Path
from monstr.util import ConfigError
from monstr.ident.keystore import NamedKeys, SQLiteKeyStore, KeystoreInterface, KeyDataEncrypter
from monstr.encrypt import Keys, DecryptionException

# defaults if not otherwise given
# working directory it'll be created it it doesn't exist
WORK_DIR = f'{Path.home()}/.nostrpy/'
# name of the db file
FILE_NAME = 'keystore.db'


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


async def profile_creator():
    file_name = WORK_DIR + FILE_NAME


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
                        default=file_name,
                        type=str,
                        help='mappings in this file, default is %s ' % file_name)
    parser.add_argument('profile_name',
                        nargs='?',
                        type=str,
                        help='profile_name to perform action on')
    parser.add_argument('-k',
                        '--keys',
                        help='npub/nsec for the profile',
                        default=None)

    # opts, args = getopt.getopt(sys.argv[1:], 'hdnlf:', ['help',
    #                                                     'debug,'
    #                                                     'new',
    #                                                     'link'])
    #
    # # attempt interpret action
    # for o, a in opts:
    #     print(o,a)
    args = vars(parser.parse_args())
    profile_name = args['profile_name']
    keys = args['keys']

    # get password for encryptor
    async def get_key() -> str:
        # get password to unlock keystore
        return getpass('keystore key: ')

    # the key store, with encryptor for keys
    key_store = SQLiteKeyStore(file_name=args['filename'],
                               encrypter=KeyDataEncrypter(get_key))


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
            if profile_name is None:
                print('profile name is required')
            else:
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
        print(f'bad password or non encryted store? - {de}')
    except Exception as e:
        print(e)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    logging.getLogger().setLevel(logging.ERROR)
    asyncio.run(profile_creator())





