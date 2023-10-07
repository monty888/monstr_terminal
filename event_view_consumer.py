#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  Simple json dump of the event viewer demonstrating
  how easy it is to play around with the events read
  from nostr without having to implement a full client.

    Usage when you use a config file:
        $ ./python3 event_view.py -o json | ./event_view_consumer.py

    or, if you want to use a specific  nostr relay instance:
        $ python3 event_view.py -r wss://nos.lol -o json | python3 event_view_consumer.py
"""

import fileinput
import json
import pprint


if __name__ == '__main__':
    for line in fileinput.input():
        pprint.pprint(json.loads(line))

