import logging
import toml
import sys
from pathlib import Path
from toml import TomlDecodeError
import os


def load_toml(filename, dir):
    if os.path.sep not in filename:
        filename = dir+os.path.sep+filename

    ret = {}
    f = Path(filename)
    if f.is_file():
        try:
            ret = toml.load(filename)
        except TomlDecodeError as te:
            print('Error in config file %s - %s ' % (filename, te))
            sys.exit(2)

    else:
        logging.debug('load_toml:: no config file %s' % filename)
    return ret


class ConfigError(Exception):
    pass