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
import sys
import argparse
from pathlib import Path
from monstr.util import ConfigError
from monstr.ident.alias import ProfileFileAlias


def profile_creator():
    file_name = '%s/.nostrpy/profiles.csv' % Path.home()


    parser = argparse.ArgumentParser(description="""
        link nostr keypairs to profile names
        
        alias.py <profile_name>           view existing mapping
        alias.py -n <profile_name>        map new keys auto generated
        alias.py -n <profile_name> <key>  map new with supplied key if pub_k then view only 
        alias.py -l <profile_name> <key>  map existing to key, any exsting mapping overridden
        
    """, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-n', '--new',
                        help='create a new profile key pair link',
                        action='store_true')
    parser.add_argument('-l', '--link',
                        help='link key pair to exiting profile file, any existing mapping will be overridden',
                        action='store_true')
    parser.add_argument('-f', '--filename',
                        default=file_name,
                        type=str,
                        help='mappings in this file, default is %s ' % file_name)
    parser.add_argument('profile_name', help='profile_name to perform action on')
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
    my_profiles = ProfileFileAlias(args['filename'])
    profile_name = args['profile_name']
    keys = args['keys']

    try:
        # view only
        if args['new'] is False and args['link'] is False:
            p = my_profiles.get_profile(profile_name)
            if p:
                print(profile_name)
                print(p.keys)
            else:
                print('profile not found: %s' % profile_name)

        elif args['new'] and args['link']:
            print('--new and --link can both be True')
            sys.exit(2)
        elif args['new']:
            p = my_profiles.new_profile(profile_name=profile_name,
                                        keys=keys)
            print('created profile: %s' % profile_name)
            print(p.keys)
        elif args['link']:
            if keys is None:
                raise ConfigError('keys required to link')
            try:
                p = my_profiles.link_profile(profile_name=profile_name,
                                             keys=keys)

                print('linked keys to profile: %s' % profile_name)
                print(p.keys)
            except Exception as e:
                raise ConfigError(str(e))
    except ConfigError as ce:
        print(ce)
    except Exception as e:
        print(e)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    logging.getLogger().setLevel(logging.ERROR)
    profile_creator()





