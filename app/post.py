from __future__ import annotations

import logging
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from monstr.client.client import Client

from monstr.client.event_handlers import DeduplicateAcceptor, NotOnlyNumbersAcceptor
from monstr.event.event import Event
from monstr.ident.profile import Profile
from monstr.inbox import Inbox


class PostApp:

    # @staticmethod
    # def _get_public_key_str(k_obj: [Profile | Keys | str]):
    #     ret = k_obj
    #     if isinstance(k_obj, Profile):
    #         ret = k_obj.public_key
    #     elif isinstance(k_obj, Keys):
    #         ret = k_obj.public_key_hex()
    #
    #     if not Keys.is_hex_key(ret):
    #         raise ValueError(f'{k_obj} unable to get nostr pub_k')
    #
    #     return ret

    def __init__(self,
                 use_relay,
                 as_user: Profile,
                 to_users: [Profile],
                 inbox: Inbox = None,
                 subject=None,
                 is_encrypt=True,
                 kind=None,
                 tags=None
                 ):
        """
        :param as_user:     posts made as this user
        :param to_users:    posts will be made to these users, required if doing encrypted posts but can be set to None
                            when is_encrypt is False - in this case you'll just be in broadcast sending posts out
        :param inbox:       send events wrapped through this inbox account
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
        self._inbox = inbox

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
        if self._inbox:
            # this can return None if we failed to unwrap event for whatever reason
            evt = self._inbox.unwrap_event(evt, self._as_user.keys)

        if evt and self.accept_event(client, sub_id, evt) and evt.kind == self._kind:
            if self._is_chat(evt):
                self._msg_events.append(evt)
                if self._on_msg:
                    self._on_msg(evt)

    def set_on_message(self, callback):
        self._on_msg = callback

    def do_post(self, msg):
        for evt in self.make_post(msg):
            self._client.publish(evt)

    def show_post_info(self, msg: str=None):
        if msg is None:
            msg = '<no msg supplied>'
        just = 10
        print('from:'.rjust(just), self.as_user.display_name())
        if self._to_users:
            p: Profile
            print('to:'.rjust(just), [p.display_name() for p in self._to_users])
        if self._inbox:
            print('via:'.rjust(just), self._inbox.name)

        if self._subject:
            print('subject:'.rjust(just), self._subject)

        enc_text = 'encrypted'
        if not self._is_encrypt:
            enc_text = 'plain_text'
        print('format:'.rjust(just), enc_text)
        if self._kind not in {1, 4}:
            print('kind :'.rjust(just), self._kind)

        print('%s\n%s\n%s' % (''.join(['-'] * 10),
                              msg,
                              ''.join(['-'] * 10)))

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

        def make_event(post_to: str = None):
            ret = Event(kind=self._kind,
                        content=msg,
                        pub_key=self._as_user.public_key,
                        tags=tags)
            if post_to:
                ret.content = ret.encrypt_content(priv_key=self._as_user.private_key,
                                                  pub_key=post_to)

            ret.sign(self._as_user.private_key)
            if self._inbox:
                ret = self._inbox.wrap_event(ret,
                                             from_k=self._as_user.keys,
                                             to_k=post_to)

            return ret

        tags = []
        if self._to_users:
            tags = [['p', p.public_key] for p in self._to_users]

        if self._tags:
            tags = tags + self._tags

        if self._subject is not None:
            tags.append(['subject', self._subject])

        try:
            if not self._is_encrypt:
                post = [make_event()]

            # when it's encrypt we make as many event as to_users
            else:
                post = []
                for c_post in tags:
                    if c_post[0] == 'subject':
                        continue
                    # we leave all the p_tags - should we just restrict to who we're sending too?
                    post.append(make_event(c_post[1]))

        except Exception as e:
            pass

        return post

    @property
    def message_events(self):
        return self._msg_events

    @property
    def as_user(self) -> Profile:
        return self._as_user

    @property
    def connection_status(self):
        return self._client.connected