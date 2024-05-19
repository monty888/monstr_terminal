import logging
import toml
import sys
from pathlib import Path
from toml import TomlDecodeError
import os
from monstr.ident.alias import ProfileFileAlias
from monstr.encrypt import Keys
from monstr.util import ConfigError


def load_toml(filename, dir):
    if os.path.sep not in filename:
        filename = dir+os.path.sep+filename

    ret = {}
    f = Path(filename)
    if f.is_file():
        try:
            toml_dict = toml.load(filename)

            for n, v in toml_dict.items():
                ret[n.replace('-','_')] = v

        except TomlDecodeError as te:
            print(f'Error in config file {filename} -{te}')
            sys.exit(2)

    else:
        logging.debug(f'load_toml:: no config file {filename}')

    return ret


def get_keys_from_str(keys: str,
                      private_only=False,
                      single_only=False,
                      alias_map: ProfileFileAlias = None) -> [Keys]:
    """
    get Key objects from string e.g. that can be npub,nsec or alias and may be mutiple seperated by comma
    :param alias_map:
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
    for c_key in keys:
        # maybe have flag to allow hex keys but for now just nsec/npub as it's so easy to leak the priv_k otherwise!
        if Keys.is_bech32_key(c_key):
            the_key = Keys.get_key(c_key)

        # is it an alias?
        elif alias_map:
            p: Profile = alias_map.get_profile(c_key)
            if p:
                the_key = p.keys
            else:
                raise ConfigError(f'{c_key} doesn\'t look like a nsec/npub nostr key or alias not found')
        else:
            raise ConfigError(f'{c_key} doesn\'t look like a nsec/npub nostr key')

        if private_only and the_key.private_key_hex() is None:
            raise ConfigError(f'{c_key} is not a private key')
        ret.append(the_key)
    return ret