# install
> git clone --recurse-submodules https://github.com/monty888/monstr_terminal.git  
> cd monstr_terminal  
> python3 -m venv venv   
> source venv/bin/activate   
> pip install -r requirements.txt   
> pip install ./monstr

# event view
nostr event viewer for the command line. 

![event view screenshot](event_view.png) 


```commandline
python event_view.py --help
usage: event_view.py [-h] [-r RELAY] [-a AS_USER] [--view_profiles VIEW_PROFILES] [-v VIA] [-i EID] [-k KINDS] [-s SINCE] [-u UNTIL] [-t TAGS]
                     [-p {8,12,16,20,24,28,32}] [-n] [-o {formatted,json,content}] [-d]

view nostr events from the command line

options:
  -h, --help            show this help message and exit
  -r RELAY, --relay RELAY
                        comma separated nostr relays to connect to, default[None]
  -a AS_USER, --as_user AS_USER
                        alias, priv_k or pub_k of user to view as. If only created from pub_k then kind 4 encrypted events will be left encrypted,
                        default[None]
  --view_profiles VIEW_PROFILES
                        additional comma separated alias, priv_k or pub_k of user to view, default[None]
  -v VIA, --via VIA     additional comma separated alias(with priv_k) or priv_k that will be used as public inbox with wrapped events, default[None]
  -i EID, --id EID      comma separated event ids will be added as e tag filter e.g with kind=42 can be used to view a chat channel, default[None]
  -k KINDS, --kinds KINDS
                        comma separated event kinds to output, default[1,4]
  -s SINCE, --since SINCE
                        show events n hours previous to running, default [6]
  -u UNTIL, --until UNTIL
                        show events n hours after since, default [None]
  -t TAGS, --tags TAGS  comma separated tag types to output, =* for all default[None]
  -p {8,12,16,20,24,28,32}, --pow {8,12,16,20,24,28,32}
                        minimum amount required for events excluding contacts of as_user default[None]
  -n, --nip5            valid nip5 required for events excluding contacts of as_user
  -o {formatted,json,content}, --output {formatted,json,content}
                        how to display events default[formatted]
  -d, --debug           enable debug output
```


view all event as they come in:
```shell
python event_view.py 
```
view events for a given user, also an extra user that's not in thier follows and check in additional inbox:
```shell
python event_view.py --as=<key or alias> --view=<key or alias> --via=<key or alias>
````
note that the view will be made by looking up the contacts event for the given key so that needs to be available 
on the used relays. When a user is given encrypted text will automatically be decrypted. 


# poster
post text(kind 1) or encrypted(kind 4) text notes to nostr from the command line. Optionally via a inbox 
an account for which bother poster and receiver have priv key so that meta is hidden.

```commandline
usage: poster.py [-h] [-r RELAY] [-a AS_USER] [-t TO_USERS] [-v VIA] [-s SUBJECT] [-p]
                 [-i] [-l] [-d]
                 [message ...]

post nostr text(1) and encrypted text(4) events from the command line

positional arguments:
  message               an integer for the accumulator

options:
  -h, --help            show this help message and exit
  -r RELAY, --relay RELAY
                        comma separated nostr relays to connect to,
                        default[ws://localhost:8081]
  -a AS_USER, --as_user AS_USER
                        alias, priv_k of user to post as, default[monty]
  -t TO_USERS, --to_users TO_USERS
                        comma seperated alias, priv_k, or pub_k of user to post to,
                        default[None]
  -v VIA, --via VIA     alias(with priv_k) or nsec that will be used as public inbox
                        with wrapped events, default[None]
  -s SUBJECT, --subject SUBJECT
                        add subject tag to post,, default[None]
  -p, --plain_text      post as plain text
  -i, --ignore_missing  don't fail on missing to_users
  -l, --loop            stay open to enter and receive messages
  -d, --debug           enable debug output

```

![poster open in loopmode](poster.png)

### examples
send a plain text post:
```shell
python poster.py -p --as=<key or alias> hello there
```
send encrypted post to another user:
```shell
python poster.py --as=<key or alias> --to=<key or alias> hello there
```
plain post in loop mode using a mailbox - only other users with key to the mailbox will be able to view messages: 
```shell
python poster.py -pl --as=<key or alias> --via=<key or alias>
```
# alias
creates named aliases to keys so they can be referenced by user friendly name.
```commandline
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
```
### examples
create a new key and alias monty:
```shell
python alias.py -n monty        
```
create a new profile and link to an existing known nsec/npub
```
python alias.py -n monty -k nsec.... 
```
# relay
basic relay implementation:

```commandline
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
                        default[/{home}/.nostrpy/nostr-relay.db]
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

```
### examples
run relay without storing any events
```shell
python run_relay.py --store=none       
```
wipe the default (sqlite) db
```
python run_relay.py --w
```

# profile search

builds up a local list of profiles for searching from the command line

```commandline
usage: profile_search.py [-h] [-r RELAY] [-a AS_USER] [-b BOOTSTRAP] [-s SINCE] [-d]

search for nostr user profiles

options:
  -h, --help            show this help message and exit
  -r RELAY, --relay RELAY
                        comma separated urls of relays to connect to - default ws://localhost:8081
  -a AS_USER, --as_user AS_USER
                        nsec/npub/hex or alias for account viewing as - default None
  -b BOOTSTRAP, --bootstrap BOOTSTRAP
                        nsec/npub/hex or alias for accounts used for bootstrapping - default None
  -s SINCE, --since SINCE
                        n days to search back for profile events - default 5
  -d, --debug           enable debug output

```

### examples

start running with as alias monty attach to relay nos.lol
```shell
python profile_search.py --as=monty --relay=wss://nos.lol       
```

on running at the > prompt type text to preform a search of seen profiles.
  
type 'exit' to quit

also follow commands are available:
* $count - returns count of profiles in cache 
* $profile {nsec/npub} [short|long|json]- show profile meta data
* $contacts {nsec/npub} [short|long|json] - show profile meta for contacts of given key
* $posts {nsec/npup} - show last 10 post for profile