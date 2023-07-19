from __future__ import annotations

import logging
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from monstr.client.client import Client

import json
import hashlib
from monstr.client.event_handlers import DeduplicateAcceptor, DuplicateContentAcceptor, NotOnlyNumbersAcceptor
from monstr.encrypt import SharedEncrypt
from monstr.event.event import Event
from monstr.ident.profile import Profile


class PostApp:

    @staticmethod
    def get_clust_shared(echd_key):
        return hashlib.sha256(echd_key.encode()).hexdigest()

    @staticmethod
    def get_clust_shared_keymap_for_profile(as_user: Profile, to_users: [] = None):
        """
        :param as_user: user profile that we're mapping shared keys for
        :param to_users: [] either of pubkeys or Profiles
        :return:
        """
        se = SharedEncrypt(as_user.private_key)

        ret = {PostApp.get_clust_shared(se.derive_shared_key(as_user.public_key)): as_user.public_key}

        c_p: Profile
        if to_users:
            for c_p in to_users:
                for_key = c_p
                if isinstance(for_key, Profile):
                    for_key = c_p.public_key

                ret[PostApp.get_clust_shared(se.derive_shared_key(for_key))] = for_key

        return ret

    @staticmethod
    def clust_unwrap_event(evt: Event, as_user: Profile, shared_keys_map: set, inbox_decode_map: dict):
        ret = None
        shared_tags = evt.get_tags('shared')
        if shared_tags and shared_tags[0][0] in shared_keys_map:
            try:
                content = evt.decrypted_content(as_user.private_key, shared_keys_map[shared_tags[0][0]])
                ret = Event.from_JSON(json.loads(content))
            except Exception as e:
                pass
        else:
            # is just a plain text in a public inbox? anyone with the private key to the inbox can see it
            try:
                decode_key = inbox_decode_map[evt.pub_key]
                content = evt.decrypted_content(decode_key, evt.pub_key)
                ret = Event.from_JSON(json.loads(content))
            except Exception as e:
                pass

        return ret

    def __init__(self,
                 use_relay,
                 as_user: Profile,
                 to_users: [Profile],
                 public_inbox: Profile = None,
                 subject=None,
                 is_encrypt=True,
                 kind=None,
                 tags=None
                 ):
        """
        :param as_user:     posts made as this user
        :param to_users:    posts will be made to these users, required if doing encrypted posts but can be set to None
                            when is_encrypt is False - in this case you'll just be in broadcast sending posts out
        :param public_inbox: if set then posts will be wrapped and sent via this inbox which all users will need the
                            private key to, as CLUST see ....
        :param subject:     subject tag will be added to msgs and used as a filter also to see replies
        :param is_encrypt:  if true then NIP4 encoded

        TODO: we should probably do some checking on init values, at the moment we're expecting th ecaller to do

        """
        self._client = use_relay
        self._as_user = as_user
        self._to_users = to_users
        self._chat_members = self._create_chat_members()
        self._public_inbox = None
        self._shared_keys = None
        self._set_public_inbox(public_inbox)

        self._subject = subject

        self._is_encrypt = is_encrypt

        # default kinds for encrypt/no encrypt
        if kind is None:
            if self._is_encrypt:
                self._kind = 4
            else:
                self._kind = 1

        # not, doesn't stop you from encrypting data send e.g. over kind 1 though you probably don't want to do that
        else:
            self._kind = kind

        # tags to be added to every post
        self._tags = tags

        # de-duplicating of events for when we're connected to multiple relays
        self._acceptors = [
            DeduplicateAcceptor(),
            # bit crap needs the message to be exacly the same, better if it was using matching patterns and with whitelist
            # DuplicateContentAcceptor(),
            # if content is just numbers then reject, again whitelist would be good
            NotOnlyNumbersAcceptor()
        ]

        # all the mesages we've seen, if since and event store then may be some from before we started
        self._msg_events = []
        self._on_msg = None

    def _create_chat_members(self):
        ret = set([self._as_user.public_key])

        if self._to_users:
            ret = ret.union(set([p.public_key for p in self._to_users]))
        ret = list(ret)
        ret.sort()
        return ret

    def _set_public_inbox(self, public_inbox):
        self._public_inbox = public_inbox
        if public_inbox is None:
            self._shared_keys = None
        else:
            # self._shared_keys = PostApp.get_clust_shared_for_profile(self._as_user, self._to_users)
            self._shared_keys = PostApp.get_clust_shared_keymap_for_profile(self.as_user, self._to_users)

    def _is_chat(self, msg: Event):
        """
        is this msg part of the chat we're looking at, currently this is just made
        up by have all the correct members in it, so if all the members are the same
        then you're looking in that group...
        TODO: look at proper group chat NIP and implement

        :param msg:
        :return:
        """

        msg_members = list(set([msg.pub_key]).union(msg.p_tags))
        msg_members.sort()

        if self._subject:
            is_subject = False
            if msg.get_tags('subject'):
                is_subject = self._subject in [s[0] for s in msg.get_tags('subject')]
        else:
            is_subject = True

        return self._chat_members == msg_members and is_subject or (self._is_encrypt is False and self._to_users is None)

    def accept_event(self,
                     the_client: Client,
                     sub_id: str,
                     evt: Event) -> bool:
        ret = True
        for c_accept in self._acceptors:
            try:
                ret = c_accept.accept_event(the_client, sub_id, evt)
                if not ret:
                    break
            except Exception as e:
                logging.debug(e)
        return ret

    def do_event(self, client: Client, sub_id, evt: Event):
        if self.accept_event(client, sub_id, evt):
            # unwrap if evt is shared
            if self._public_inbox:
                if evt.pub_key == self._public_inbox.public_key:
                    evt = PostApp.clust_unwrap_event(evt, self._as_user, self._shared_keys, {
                        self._public_inbox.keys.public_key_hex(): self._public_inbox.keys.private_key_hex()
                    })
                    if self._is_encrypt and evt and evt.kind != Event.KIND_ENCRYPT:
                        evt = None
                    elif not self._is_encrypt and evt and evt.kind != Event.KIND_TEXT_NOTE:
                        evt = None
                        #
                        #
                        # try:
                        #     se = SharedEncrypt(self._public_inbox.private_key)
                        #     se.derive_shared_key(self._public_inbox.public_key)
                        #     evt = evt.decrypted_content(self._public_inbox.private_key, se.shared_key())
                        # except Exception as e:
                        #     pass

                else:
                    evt = None

            # evt None if using public_box and couldn't unwrap
            if evt is not None and self._is_chat(evt):
                self._msg_events.append(evt)
                if self._on_msg:
                    self._on_msg(evt)

    def set_on_message(self, callback):
        self._on_msg = callback

    def do_post(self, msg):
        for evt in self.make_post(msg):
            self._client.publish(evt)

    def make_post(self, msg) -> Event:
        """
        makes post events, a single event if plaintext or 1 per to_user if encrypted
        :param public_inbox:
        :param as_user:
        :param msg:
        :param to_users:
        :param is_encrypt:
        :param subject:
        :return:
        """
        tags = []
        if self._to_users:
            tags = [['p', p.public_key] for p in self._to_users]

        if self._tags:
            tags = tags + self._tags

        if self._subject is not None:
            tags.append(['subject', self._subject])

        if not self._is_encrypt:
            evt = Event(kind=self._kind,
                        content=msg,
                        pub_key=self._as_user.public_key,
                        tags=tags)

            evt.sign(self._as_user.private_key)
            if self._public_inbox:
                evt = self._inbox_wrap(evt)
            post = [evt]

        else:
            post = []
            for c_post in tags:
                if c_post[0] == 'subject':
                    continue
                evt = Event(kind=self._kind,
                            content=msg,
                            pub_key=self._as_user.public_key,
                            tags=tags)
                evt.content = evt.encrypt_content(priv_key=self._as_user.private_key,
                                                  pub_key=c_post[1])
                evt.sign(self._as_user.private_key)

                if self._public_inbox:
                    evt = self._inbox_wrap(evt,
                                           to_pub_k=c_post[1])

                post.append(evt)

        return post

    def _inbox_wrap(self, evt, to_pub_k=None):
        tags = []
        if to_pub_k:
            se = SharedEncrypt(self._as_user.private_key)
            se.derive_shared_key(to_pub_k)
            tags = [
                    ['shared', PostApp.get_clust_shared(se.shared_key())]
            ]

        evt = Event(kind=Event.KIND_ENCRYPT,
                    content=json.dumps(evt.event_data()),
                    pub_key=self._public_inbox.public_key,
                    tags=tags)
        # evt.content = evt.encrypt_content(self._public_inbox.private_key, to_pub_k)
        if to_pub_k:
            evt.content = evt.encrypt_content(self._as_user.private_key, to_pub_k)
        else:
            evt.content = evt.encrypt_content(self._public_inbox.private_key, self._public_inbox.public_key)

        evt.sign(self._public_inbox.private_key)
        return evt


    @property
    def message_events(self):
        return self._msg_events

    @property
    def as_user(self) -> Profile:
        return self._as_user

    @property
    def connection_status(self):
        return self._client.connected