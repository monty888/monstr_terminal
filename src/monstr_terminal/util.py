import logging
import toml
import sys
from pathlib import Path
from toml import TomlDecodeError
import os
from monstr.encrypt import Keys
from monstr.util import ConfigError
from monstr.ident.keystore import SQLiteKeyStore, NIP49KeyDataEncrypter, KeystoreInterface
from monstr.signing.signing import SignerInterface, BasicKeySigner
from monstr.signing.nip46 import NIP46Signer
from getpass import getpass


def load_toml(filename, dir, current_args):
    if os.path.sep not in filename:
        filename = dir+os.path.sep+filename

    f = Path(filename)
    if f.is_file():
        try:
            toml_dict = toml.load(filename)

            for n, v in toml_dict.items():
                n = n.replace('-','_')
                if n in current_args:
                    c_v = current_args[n]
                    if isinstance(c_v, dict):
                        for k, v in v.items():
                            c_v[k] = v
                    else:
                        current_args[n] = v

                else:
                    current_args[n] = v

        except TomlDecodeError as te:
            print(f'Error in config file {filename} -{te}')
            sys.exit(2)

    else:
        logging.debug(f'load_toml:: no config file {filename}')


async def get_key_from_str(key: str,
                           private_only=False,
                           key_store: KeystoreInterface = None) -> Keys:
    """
    given key str try to make a Key obj
    :param key:            , seperated nsec/npub
    :param private_only:    only accept keys that we can sign with
    :param key_store:
    :return: Key
    """

    # if it's a bech32 str then convert to key obj
    if Keys.is_bech32_key(key):
        ret = Keys.get_key(key)
    # else we'll have a look in the key_store if one was given
    elif key_store:
        ret = await key_store.get(key)
        if ret is None:
            raise ConfigError(f'{key} doesn\'t look like a nsec/npub nostr key or alias not found')
    else:
        raise ConfigError(f'{key} doesn\'t look like a nsec/npub nostr key')

    if private_only and ret.private_key_hex() is None:
        raise ConfigError(f'{key} is not a private key')

    return ret


async def get_signer_from_str(key: str,
                              key_store: KeystoreInterface = None) -> SignerInterface:

    if key.lower().startswith('bunker://'):
        ret = NIP46Signer(key, auto_start=True)
    else:
        ret = BasicKeySigner(await get_key_from_str(key=key,
                                                    key_store=key_store,
                                                    private_only=True))

    return ret


async def get_keys_from_str(keys: str,
                            private_only=False,
                            key_store: KeystoreInterface = None) -> [Keys]:
    """
    get Key objects from string e.g. that can be npub,nsec or alias and may be mutiple seperated by comma
    :param key_store:
    :param keys:            , seperated nsec/npub
    :param private_only:    only accept nsec
    :param single_only:     only a single key
    :return: [Key]
    """

    if ',' in keys:
        key_arr = keys.split(',')
    else:
        key_arr = [keys]
    return [await get_key_from_str(key=k,
                                   private_only=private_only,
                                   key_store=key_store)for k in key_arr]


def get_sqlite_key_store(db_file, password: str = None):
    # human alias to keys
    # keystore for user key aliases
    async def get_password() -> str:
        ret = password
        if password is None:
            ret = getpass('keystore key: ')
        return ret

    key_enc = NIP49KeyDataEncrypter(get_password=get_password)
    return SQLiteKeyStore(file_name=db_file,
                          encrypter=key_enc)
