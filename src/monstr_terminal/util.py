import logging
import toml
import sys
from pathlib import Path
from toml import TomlDecodeError
import os
from monstr.encrypt import Keys
from monstr.util import ConfigError
from monstr.ident.keystore import SQLiteKeyStore, KeyDataEncrypter, KeystoreInterface
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


async def get_keys_from_str(keys: str,
                            private_only=False,
                            single_only=False,
                            key_store: KeystoreInterface = None) -> [Keys]:
    """
    get Key objects from string e.g. that can be npub,nsec or alias and may be mutiple seperated by comma
    :param key_store:
    :param keys:            , seperated nsec/npub
    :param private_only:    only accept nsec
    :param single_only:     only a single key
    :return: [Key]
    """
    if single_only:
        keys = [keys]
    else:
        keys = keys.split(',')

    ret = []
    for k_str in keys:
        # maybe have flag to allow hex keys but for now just nsec/npub as it's so easy to leak the priv_k otherwise!
        if Keys.is_bech32_key(k_str):
            k = Keys.get_key(k_str)

        # is it an alias - check the keystore if we've been given one
        elif key_store:
            k = await key_store.get(k_str)

            if k is None:
                raise ConfigError(f'{k_str} doesn\'t look like a nsec/npub nostr key or alias not found')
        else:
            raise ConfigError(f'{k_str} doesn\'t look like a nsec/npub nostr key')

        if private_only and k.private_key_hex() is None:
            raise ConfigError(f'{k_str} is not a private key')
        ret.append(k)
    return ret


def get_sqlite_key_store(db_file, password: str = None):
    # human alias to keys
    # keystore for user key aliases
    async def get_key() -> str:
        ret = password
        if password is None:
            ret =  getpass('keystore key: ')
        return ret

    key_enc = KeyDataEncrypter(get_key=get_key)
    return SQLiteKeyStore(file_name=db_file,
                          encrypter=key_enc)
