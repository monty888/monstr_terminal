"""
usage: run_relay.py [-h] [--host HOST] [--port PORT] [--endpoint ENDPOINT]
                    [-s {sqlite,postgres,transient,none}] [--dbfile DBFILE]
                    [--pg_database PG_DATABASE] [--pg_user PG_USER]
                    [--pg_password PG_PASSWORD] [--maxsub MAXSUB]
                    [--maxlength MAXLENGTH] [--nip15] [--nip16] [--nip20] [-w] [-d]

runs a nostr relay

options:
  -h, --help            show this help message and exit
  --host HOST           ip address where relay will listen, default[localhost]
  --port PORT           port relay will listen, default[8081]
  --endpoint ENDPOINT   endpoint address for the relay websocket[/]
  -s {sqlite,postgres,transient,none}, --store {sqlite,postgres,transient,none}
                        storage type to use for received events, default[sqlite]
  --dbfile DBFILE       when store is sqlite the file location for the db,
                        default[/{home}}/.nostrpy/nostr-relay.db]
  --pg_database PG_DATABASE
                        when store is postgres the postgres db name, default[nostr-
                        relay]
  --pg_user PG_USER     when store is postgres the postgres username,
                        default[postgres]
  --pg_password PG_PASSWORD
                        when store is postgres the postgres password
  --maxsub MAXSUB       maximum open subs allowed per client websocket, default[10]
  --maxlength MAXLENGTH
                        maximum length for event content if any, default[None]
  --nip15               disable NIP15 - End Of Stored Events(EOSE) see
                        https://github.com/nostr-protocol/nips/blob/master/15.md,
                        default[False]
  --nip16               disable NIP16 - Event treatment, ephemeral and replaceable
                        event ranges see https://github.com/nostr-
                        protocol/nips/blob/master/16.md, default[False]
  --nip20               disable NIP20 - OK command events see
                        https://github.com/nostr-protocol/nips/blob/master/20.md,
                        default[False]
  -w, --wipe            wipes event store and exits
  -d, --debug           enable debug output
"""
import logging
import sys
import os
import asyncio
import signal
import argparse
from pathlib import Path
from monstr.relay.relay import Relay
from monstr.relay.accept_handlers import LengthAcceptReqHandler
from monstr.event.persist import RelayMemoryEventStore, ARelaySQLiteEventStore, RelayPostgresEventStore
from util import load_toml

# default values when nothing is specified either from cmd line or config file
HOST = 'localhost'
PORT = 8081
END_POINT = '/'
DEBUG_LEVEL = logging.DEBUG
DB_TYPE = 'sqlite'
# make this default home, wouldn't work on windows
WORK_DIR = f'{Path.home()}/.nostrpy/'
CONFIG_FILE = WORK_DIR + 'relay.toml'
SQL_LITE_FILE = f'{WORK_DIR}nostr-relay.db'
PG_USER = 'postgres'
PG_PASSWORD = 'password'
PG_DATABASE = 'nostr-relay'
MAX_SUB = 10
MAX_CONTENT_LENGTH = None


def create_work_dir():
    if not os.path.isdir(WORK_DIR):
        logging.info(f'create_work_dir:: attempting to create {WORK_DIR}')
        os.makedirs(WORK_DIR)


async def get_sql_store(filename, is_nip16):
    f = Path(filename)

    parent_dir = f.parts[len(f.parts)-2]

    # user must have given another dir, we better check it exists...
    if parent_dir != '.nostrpy':
        my_dir = Path(os.path.sep.join(f.parts[:-1]).replace(os.path.sep+os.path.sep, os.path.sep))
        if not my_dir.is_dir():
            print(f'sqllite dir not found {my_dir}')
            sys.exit(2)

    # if the file doesn't exist it'll be created and we'll create the db struct too
    # if it does we'll assume everything is ok...we could do more

    ret = ARelaySQLiteEventStore(filename,
                                 is_nip16=is_nip16)
    if not ret.exists():
        logging.info(f'get_sql_store::create new db {filename}')
        await ret.create()
    else:
        logging.info(f'get_sql_store::open existing db {filename}')

    return ret


def get_postgres_store(db_name, user, password, is_nip16):
    ret = RelayPostgresEventStore(db_name=db_name,
                                  user=user,
                                  password=password,
                                  is_nip16=is_nip16)

    if not ret.exists():
        ret.create()
    return ret


def get_cmdline_args(args) -> dict:
    parser = argparse.ArgumentParser(
        prog='run_relay.py',
        description="""
            runs a nostr relay
            """
    )
    parser.add_argument('--host', action='store', default=args['host'],
                        help=f'ip address where relay will listen, default[{args["host"]}]')
    parser.add_argument('--port', action='store', default=args['port'], type=int,
                        help=f'port relay will listen, default[{args["port"]}]')
    parser.add_argument('--endpoint', action='store', default=args['endpoint'],
                        help=f'endpoint address for the relay websocket[{args["endpoint"]}]')
    parser.add_argument('-s', '--store', action='store', default=args['store'],
                        choices=['sqlite', 'postgres', 'transient', 'none'],
                        help=f'storage type to use for received events, default[{args["store"]}]')

    # sqlite store stuff
    parser.add_argument('--dbfile', action='store', default=args['dbfile'],
                        help=f'when store is sqlite the file location for the db, default[{args["dbfile"]}]')
    # postgres store stuff
    parser.add_argument('--pg_database', action='store', default=args['pg_database'],
                        help=f'when store is postgres the postgres db name, default[{args["pg_database"]}]')
    parser.add_argument('--pg_user', action='store', default=args['pg_user'],
                        help=f'when store is postgres the postgres username, default[{args["pg_user"]}]')
    parser.add_argument('--pg_password', action='store', default=args['pg_password'],
                        help=f'when store is postgres the postgres password')
    # general relay operation

    parser.add_argument('--maxsub', action='store', default=args['maxsub'], type=int,
                        help=f'maximum open subs allowed per client websocket, default[{args["maxsub"]}]')
    parser.add_argument('--maxlength', action='store', default=args['maxlength'], type=int,
                        help=f'maximum length for event content if any, default[{args["maxlength"]}]')
    # nip support flags as flag is to turn off they're output not'ed
    parser.add_argument('--nip15', action='store_true',
                        help=f"""disable NIP15 - End Of Stored Events(EOSE)
                see https://github.com/nostr-protocol/nips/blob/master/15.md, default[{not args["nip15"]}]""",
                        default=args['nip15'])
    parser.add_argument('--nip16', action='store_true',
                        help=f"""disable NIP16 - Event treatment, ephemeral and replaceable event ranges
                see https://github.com/nostr-protocol/nips/blob/master/16.md, default[{not args["nip16"]}]""",
                        default=args['nip16'])
    parser.add_argument('--nip20', action='store_true',
                        help=f"""disable NIP20 - OK command events  
                see https://github.com/nostr-protocol/nips/blob/master/20.md, default[{not args["nip20"]}]""",
                        default=args['nip20'])

    parser.add_argument('-w', '--wipe', action='store_true', help='wipes event store and exits', default=args['debug'])
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

    # set up the defaults if not overriden
    # add config option so we can have different files and also make workdir conf?
    ret = {
        'host': HOST,
        'port': PORT,
        'endpoint': END_POINT,
        'store': DB_TYPE,
        'dbfile': SQL_LITE_FILE,
        'pg_database': PG_DATABASE,
        'pg_user': PG_USER,
        'pg_password': PG_PASSWORD,
        'maxsub': MAX_SUB,
        'maxlength': MAX_CONTENT_LENGTH,
        'nip15': True,
        'nip16': True,
        'nip20': True,
        'debug': False
    }

    # now form config file if any
    ret.update(load_toml(CONFIG_FILE))

    # now from cmd line
    ret.update(get_cmdline_args(ret))

    # if debug flagged enable now
    if ret['debug'] is True:
        logging.getLogger().setLevel(logging.DEBUG)

    # remove any config not required because of storage choice
    if ret['store'] != 'sqlite':
        del ret['dbfile']
    if ret['store'] != 'postgres':
        del ret['pg_database']
        del ret['pg_user']
        del ret['pg_password']

    # don't out the password
    ret_out = ret
    if 'pg_password' in ret:
        ret_out['pg_password'] = '****'

    if ret['debug']:
        logging.debug(f'get_args:: running with options - {ret}')

    return ret


async def main(args):
    is_wipe = args['wipe']
    create_work_dir()

    # relay addressing
    host = args['host']
    port = args['port']
    end_point = args['endpoint']

    # sub options
    max_sub = args['maxsub']
    max_length = args['maxlength']

    # get nip flags
    nip15 = args['nip15']
    nip16 = args['nip16']
    nip20 = args['nip20']

    # get the store type we're using and create
    store = args['store']
    my_store = None

    # create storage object which is either to sqllite, posgres or transient
    if store == 'sqlite':
        my_store = await get_sql_store(filename=args['dbfile'],
                                       is_nip16=nip16)
    elif store == 'postgres':
        my_store = get_postgres_store(db_name=args['pg_database'],
                                      user=args['pg_user'],
                                      password=args['pg_password'],
                                      is_nip16=nip16)
        # blank the password from printout
        args['pg_password'] = '***'

    elif store == 'transient':
        my_store = RelayMemoryEventStore(is_nip16=nip16)

    # just running to empty db
    if is_wipe:
        if store not in ('transient', 'none'):
            my_store.destroy()
        else:
            print(f'{store} store, no action required!')
        sys.exit(0)

    # optional message accept handlers
    accept_handlers = []
    if max_length:
        accept_handlers.append(LengthAcceptReqHandler(max=max_length))

    for c_handler in accept_handlers:
        logging.info(c_handler)

    logging.debug(f'config = {args}')

    my_relay = Relay(my_store,
                     max_sub=max_sub,
                     accept_req_handler=accept_handlers,
                     enable_nip15=nip15,
                     ack_events=nip20)

    print(f'running relay at {host}:{port}{end_point} persiting events to store {store}')
    await my_relay.start(host=host,
                         port=port,
                         end_point=end_point)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)

    def sigint_handler(signal, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)
    asyncio.run(main(get_args()))

