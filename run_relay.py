import logging
import sys
import os
import asyncio
import signal
import argparse
from copy import copy
from pathlib import Path
import shutil
try:
    from stem.control import Controller
except Exception as e:
    pass
from monstr.relay.relay import Relay
from monstr.relay.accept_handlers import LengthAcceptReqHandler, CreateAtAcceptor, AuthenticatedAcceptor
from monstr.event.persist_postgres import RelayPostgresEventStore
from monstr.event.persist_sqlite import ARelaySQLiteEventStore
from monstr.event.persist_memory import RelayMemoryEventStore
from monstr.event.expire import ASQLiteNIP40Expirer, MemoryNIP40Expirer
from monstr.util import ConfigError
from monstr_terminal.util import load_toml
import ssl

# default values when nothing is specified either from cmd line or config file
HOST = 'localhost'
PORT = 8081
END_POINT = '/'
DEBUG_LEVEL = logging.DEBUG
DB_TYPE = 'sqlite'
# make this default home, wouldn't work on windows
WORK_DIR = f'{Path.home()}/.nostrpy/'
CONFIG_FILE = 'relay.toml'
SQL_LITE_FILE = f'{WORK_DIR}nostr-relay.db'
PG_USER = 'postgres'
PG_PASSWORD = 'password'
PG_DATABASE = 'nostr-relay'
MAX_SUB = 10
MAX_CONTENT_LENGTH = None
SSL = False
# acceptance created_at (mins)
MAX_BEFORE = None
MAX_AFTER = 5

def create_work_dir():
    if not os.path.isdir(WORK_DIR):
        logging.info(f'create_work_dir:: attempting to create {WORK_DIR}')
        os.makedirs(WORK_DIR)


async def get_sql_store(filename, is_nip16, is_nip33):
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
                                 is_nip16=is_nip16,
                                 is_nip33=is_nip33)
    if not ret.exists():
        logging.info(f'get_sql_store::create new db {filename}')
        await ret.create()
    else:
        logging.info(f'get_sql_store::open existing db {filename}')

    return ret


def get_postgres_store(db_name, user, password, is_nip16, is_nip33):
    ret = RelayPostgresEventStore(db_name=db_name,
                                  user=user,
                                  password=password,
                                  is_nip16=is_nip16,
                                  is_nip33=is_nip33)

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

    # nip22 acceptable created_at ranges
    parser.add_argument('--max-before', action='store', default=args['max_before'], type=int,
                        help=f'maximum time before current time to accept created_at of events if any (mins), default[{args["max_before"]}]')
    parser.add_argument('--max-after', action='store', default=args['max_after'], type=int,
                        help=f'maximum time after current time to accept created_at of events if any (mins), default[{args["max_after"]}]')

    # nip support flags, both enable and disable versions so a def true can be overriden
    parser.add_argument('--nip16', action='store_true',
                        help=f"""enable NIP16 - Event treatment, ephemeral and replaceable event ranges
                see https://github.com/nostr-protocol/nips/blob/master/16.md, default[{args["nip16"]}]""",
                        default=args['nip16'])

    parser.add_argument('--no-nip16', action='store_false',dest='nip16',
                        help=f"""disable NIP16, default[{not args["nip16"]}]""",
                        default=args['nip16'])

    parser.add_argument('--nip20', action='store_true',
                        help=f"""enable NIP20 - OK command events  
                see https://github.com/nostr-protocol/nips/blob/master/20.md, default[{args["nip20"]}]""",
                        default=args['nip20'])
    parser.add_argument('--no-nip20', action='store_false',dest='nip20',
                        help=f"""disable NIP20, default[{not args["nip20"]}]""",
                        default=args['nip20'])

    parser.add_argument('--nip33', action='store_true',
                        help=f"""enable NIP33 - Parameterized Replaceable Events
                    see https://github.com/nostr-protocol/nips/blob/master/20.md, default[{args["nip33"]}]""",
                        default=args['nip33'])
    parser.add_argument('--no-nip33', action='store_false',dest='nip33',
                        help=f"""disable NIP33, default[{not args["nip33"]}]""",
                        default=args['nip33'])

    parser.add_argument('--nip40', action='store_true',
                        help=f"""enable NIP40 - Expiration Timestamp
                        see https://github.com/nostr-protocol/nips/blob/master/40.md, default[{args["nip40"]}]""",
                        default=args['nip40'])
    parser.add_argument('--no-nip40', action='store_false', dest='nip40',
                        help=f"""disable NIP40, default[{not args["nip40"]}]""",
                        default=args['nip40'])

    # TODO: add extra support file list of keys, or to use list event by given pub_k to set access keys
    parser.add_argument('--nip42', action='store_true',
                        help=f"""enable NIP42 - Authentication of clients to relays
                            see https://github.com/nostr-protocol/nips/blob/master/42.md, default[{args["nip42"]}]""",
                        default=args['nip42'])
    parser.add_argument('--no-nip42', action='store_false', dest='nip42',
                        help=f"""disable NIP42, default[{not args["nip42"]}]""",
                        default=args['nip42'])

    # end nips
    parser.add_argument('--ssl', action='store_true', help='run ssl ssl_key and ssl_cert will need to be defined',
                        default=args['ssl'])
    parser.add_argument('--tor', action='store_true', help='make realy accessable over tor',
                        default=args['tor'])
    parser.add_argument('-w', '--wipe', action='store_true', help='wipes event store and exits', default=False)
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
        'max_before': MAX_BEFORE,
        'max_after': MAX_AFTER,
        'nip16': True,
        'nip20': True,
        'nip33': True,
        'nip40': True,
        'nip42': False,
        'ssl': SSL,
        'ssl_key': None,
        'ssl_cert': None,
        'tor': False,
        'tor_password': None,
        'tor_service_dir': None,
        'tor_empheral': True,
        'debug': False
    }

    # now form config file if any
    ret.update(load_toml(dir=WORK_DIR,
                         filename=CONFIG_FILE))

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
    ret_out = copy(ret)
    if 'pg_password' in ret:
        ret_out['pg_password'] = '****'

    if ret['debug']:
        logging.debug(f'get_args:: running with options - {ret}')

    if ret['ssl']:
        if ret['ssl_key'] is None or ret['ssl_cert'] is None:
            raise ConfigError('both ssl_key and ssl_cert options must be provide to run as ssl')

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

    # nip22 created out acceptable
    max_before = args['max_before']
    if max_before:
        max_before = max_before * 60
    max_after = args['max_after']
    if max_after:
        max_after = max_after * 60

    # get nip flags
    nip16 = args['nip16']
    nip20 = args['nip20']
    nip33 = args['nip33']
    nip40 = args['nip40']
    nip42 = args['nip42']


    # ssl options
    is_ssl = args['ssl']
    ssl_cert = args['ssl_cert']
    ssl_key = args['ssl_key']

    # relay information NIP11
    relay_info = {
        'software': 'https://github.com/monty888/monstr_terminal',
        'version': '0.1.1'
    }
    # copy fields from args - from TOML file
    if 'relay_information' in args:
        for k, v in args['relay_information'].items():
            # only these fields will be added
            if k in {'name', 'pubkey', 'contact'}:
                relay_info[k] = v


    # empheral is easier as doesn't need to access any files
    # password, service_dir and empheral can only be se in toml currently
    enable_tor = args['tor']
    tor_password = args['tor_password']
    tor_dir = args['tor_service_dir']
    tor_empheral = args['tor_empheral']

    # get the store type we're using and create
    store = args['store']
    my_store = None
    my_expire = None
    # if expiration enable, events removed every 5 mins
    expire_interval = 60*5

    # create storage object which is either to sqllite, posgres or transient
    if store == 'sqlite':
        my_store = await get_sql_store(filename=args['dbfile'],
                                       is_nip16=nip16,
                                       is_nip33=nip33)
        if nip40:
            my_expire = ASQLiteNIP40Expirer(db=my_store.DB,
                                            interval=expire_interval)

    # Postgres store at the moment ios fucked and needs fixing... shouldn't be too much work
    elif store == 'postgres':
        my_store = get_postgres_store(db_name=args['pg_database'],
                                      user=args['pg_user'],
                                      password=args['pg_password'],
                                      is_nip16=nip16,
                                      is_nip33=nip33)
        # blank the password from printout
        args['pg_password'] = '***'
        if nip40:
            print('WARNING: NIP40 set true but currently no expirer for postgres so won\'t be enabled')

    elif store == 'transient':
        my_store = RelayMemoryEventStore(is_nip16=nip16,
                                         is_nip33=nip33)
        if nip40:
            my_expire = MemoryNIP40Expirer(interval=expire_interval,
                                           store=my_store)

    # if we have an event expirer start it
    if my_expire:
        asyncio.create_task(my_expire.run())
        relay_info['supported_nips'] = [40]


    # just running to empty db
    if is_wipe:
        if store not in ('transient', 'none'):
            my_store.destroy()
        else:
            print(f'{store} store, no action required!')
        sys.exit(0)

    # optional message accept handlers
    accept_handlers = []
    if nip42:
        accept_handlers.append(AuthenticatedAcceptor())
    if max_length:
        accept_handlers.append(LengthAcceptReqHandler(max=max_length))
    if max_before or max_after:
        accept_handlers.append(CreateAtAcceptor(max_before=max_before,
                                                max_after=max_after))


    for c_handler in accept_handlers:
        logging.info(c_handler)

    logging.debug(f'config = {args}')

    my_relay = Relay(my_store,
                     max_sub=max_sub,
                     accept_req_handler=accept_handlers,
                     ack_events=nip20,
                     relay_information=relay_info,
                     request_auth=nip42)

    ssl_context = None
    protocol = 'ws'
    if is_ssl:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(ssl_cert, ssl_key)
        protocol = 'wss'

    def print_run_info():
        col_size = 40
        print(f'running relay at {protocol}://{host}:{port}{end_point} persiting events to store {store}')
        for k,v in my_relay.relay_information.items():
            print(f'{k.ljust(col_size)} {v}')
        # print(my_relay.relay_information)


    # access via tor?
    if enable_tor:
        with TORService(relay_port=port,
                        service_dir=tor_dir,
                        password=tor_password,
                        isSSL=protocol=='wss',
                        empheral=tor_empheral) as my_tor:
            print_run_info()
            await my_relay.start(host=host,
                                 port=port,
                                 end_point=end_point,
                                 ssl_context=ssl_context)
    else:
        print_run_info()
        await my_relay.start(host=host,
                             port=port,
                             end_point=end_point,
                             ssl_context=ssl_context)


class TORService:

    def __init__(self, relay_port, service_dir=None, password=None, isSSL = False, empheral=True):
        try:
            if Controller:
                pass
        except NameError as ne:
            raise ConfigError(f'No Controller class - try pip install stem')

        # the relays actual port if we were to it normally
        self._relay_port = relay_port



        # password used to auth with controller
        # best to supply - but without and if tor_browser is running we still might be ok
        # (don't quite understand the exact way this is working)
        self._password = password

        # the tor service will either be on port 80 http or 443 https
        self._service_port = 80
        if isSSL:
            self._service_port = 443

        # create the tor service as empheral
        self._empheral = empheral

        # if not empheral then this is the directory where the hidden service will be created
        # just give the actual dir, the full path is worked out using the controller class
        # for example something like/home/monty/tor-browser/Browser/TorBrowser/Data/[service_dir]
        self._hidden_service_dir = service_dir
        if self._hidden_service_dir is None:
            self._hidden_service_dir = 'monstr_relay'



    def __enter__(self):
        # this will be default port probably 9051
        self._controller = Controller.from_port()
        if self._password is None:
            self._controller.authenticate()
        else:
            self._controller.authenticate(password=self._password)


        # address of service when we have it
        onion_addr = None

        # we'll get a new onion address each time
        if self._empheral:
            print(self._service_port)
            result = self._controller.create_ephemeral_hidden_service({self._service_port: self._relay_port},
                                                                      await_publication=True)

            onion_addr = result.service_id + '.onion'

        # after first create the onion address will be the same
        else:
            base_dir = self._controller.get_conf('DataDirectory', '/tmp')
            actual_dir = os.path.join(base_dir, self._hidden_service_dir)

            print(f' * Creating our hidden service {self._hidden_service_dir} in {base_dir}')
            result = self._controller.create_hidden_service(actual_dir,
                                                            self._service_port,
                                                            target_port=self._relay_port)

            onion_addr = None
            if result:
                onion_addr = result.hostname
            else:
                # probably the service already exists, try open the service_dir/hostname file
                # not sure why create_hidden_services doesn't just return that for us anyway?
                try:
                    f = open(os.path.join(actual_dir, 'hostname'), "r")
                    lines = f.readlines()
                    onion_addr = lines[0]
                except Exception as e:
                    pass

        if onion_addr:
            print(f" hidden service is available at {onion_addr}")
        else:
            print(
                f" Unable to determine our service's hostname, probably due to being unable to read the hidden service directory")


    def __exit__(self, exc_type, exc_val, exc_tb):
        print(" * Shutting down our hidden service")
        self._controller.close()
        self._controller.remove_hidden_service(self._hidden_service_dir)
        shutil.rmtree(self._hidden_service_dir)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)

    def sigint_handler(signal, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)
    try:
        asyncio.run(main(get_args()))
    except ConfigError as ce:
        print(ce)

