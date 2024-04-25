from __future__ import annotations

import logging
import asyncio
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from monstr.client.client import Client

from monstr.client.event_handlers import DeduplicateAcceptor, NotOnlyNumbersAcceptor
from monstr.event.event import Event
from monstr.ident.profile import Profile
from monstr.ident.event_handlers import ProfileEventHandlerInterface
from monstr.inbox import Inbox
from monstr.signing import SignerInterface
from monstr.encrypt import Keys


class PostApp:

    def __init__(self,
                 use_relay,
                 profile_handler: ProfileEventHandlerInterface,
                 user_sign: SignerInterface,
                 to_users_k: [Keys],
                 inbox: Inbox=None,
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
        self._profile_handler = profile_handler
        self._user_sign = user_sign
        self._to_users_k = to_users_k
        self._inbox = inbox
        self._subject = subject

        self._is_encrypt = is_encrypt

        # default kinds for encrypt/no encrypt
        if kind is None:
            if self._is_encrypt:
                self._kind = Event.KIND_ENCRYPT
            else:
                self._kind = Event.KIND_TEXT_NOTE

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

        # this are init'd by the _get_ready_task
        self._as_user: Profile = None
        self._as_user_pub_k = None
        self._to_users_p = []
        self._chat_members = []

        asyncio.create_task(self._get_ready())
        self._ready = False

    async def wait_ready(self, max_wait: int = 3):
        waited = 0.0
        while self._ready is False and int(waited) < max_wait:
            await asyncio.sleep(0.1)
            waited += 0.1

        if self._ready is False:
            raise Exception('PostApp:: wait_ready, something went wrong during setup...')

    async def _create_chat_members(self):
        chat_members = set([await self._user_sign.get_public_key()])

        k: Keys
        if self._to_users_k:
            chat_members = chat_members.union(set([k.public_key_hex() for k in self._to_users_k]))

        chat_members = list(chat_members)
        chat_members.sort()
        self._chat_members = chat_members

    async def _get_ready(self):
        # our pk
        self._as_user_pub_k = await self._user_sign.get_public_key()
        # pks we're messageing
        to_ks = []
        # ks for profiles we're going to fetch
        p_to_fetch = [self._as_user_pub_k]

        if self._to_users_k:
            to_ks = [k.public_key_hex() for k in self._to_users_k]
            p_to_fetch += to_ks

        if self._inbox:
            p_to_fetch = p_to_fetch + [await self._inbox.pub_key]

        # pre-fetch any profiles we'll need, create stubbs if they can't be found
        await self._profile_handler.aget_profiles(pub_ks=p_to_fetch,
                                                  create_missing=True)

        # get a profile obj for sending user (us)
        self._as_user = self._profile_handler.get_profile(pub_k=self._as_user_pub_k)

        # get profile only for anyone we're sending to
        self._to_users_p = self._profile_handler.get_profiles(pub_ks=to_ks)

        # create chat members, used to create the view filter
        await self._create_chat_members()

        self._ready = True

        # evts are put into a async queue to be dealt with
        self._msg_queue = asyncio.Queue()
        asyncio.create_task(self._my_consumer())

    async def _my_consumer(self):
        try:
            while True:
                args = await self._msg_queue.get()

                await self.do_event_task(*args)
        except Exception as e:
            logging.debug(f'PostApp::_my_consumer - {e}')

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

        return self._chat_members == msg_members and is_subject or (self._is_encrypt is False and not self._to_users_k)

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
        self._msg_queue.put_nowait((client, sub_id, evt))

    async def do_event_task(self, client: Client, sub_id, evt: Event):
        if self._inbox:
            try:
                # if plaintext we won't send a singer in which will stop us unwrapping encrypted
                # events event if we could
                user_sign = None
                if self._is_encrypt:
                    user_sign = self._user_sign
                # return None if we failed to unwrap
                evt = await self._inbox.unwrap_event(evt, user_sign)
            except Exception as e:
                pass

        if evt and self.accept_event(client, sub_id, evt) and evt.kind == self._kind:
            if self._is_chat(evt):
                self._msg_events.append(evt)
                if self._on_msg:
                    self._on_msg(evt)

    def set_on_message(self, callback):
        self._on_msg = callback

    async def do_post(self, msg):
        for evt in await self.make_post(msg):
            self._client.publish(evt)

    async def show_post_info(self, msg: str=None):

        if msg is None:
            msg = '<no msg supplied>'
        just = 10
        print('from:'.rjust(just), self.as_user.display_name())
        if self._to_users_p:
            p: Profile
            print('to:'.rjust(just), [p.display_name() for p in self._to_users_p])
        if self._inbox:
            print('via:'.rjust(just), await self._inbox.name)

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

    async def make_post(self, msg) -> Event:
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

        async def make_event(post_to: str = None):
            ret = Event(kind=self._kind,
                        content=msg,
                        pub_key=self._as_user_pub_k,
                        tags=tags)
            if post_to:
                ret.content = await self._user_sign.nip4_encrypt(plain_text=ret.content,
                                                                 to_pub_k=post_to)

            await self._user_sign.sign_event(ret)

            if self._inbox:
                ret = await self._inbox.wrap_event(ret,
                                                   from_sign=self._user_sign,
                                                   to_k=post_to)

            return ret

        tags = []
        if self._to_users_p:
            tags = [['p', p.public_key] for p in self._to_users_p]

        if self._tags:
            tags = tags + self._tags

        if self._subject is not None:
            tags.append(['subject', self._subject])

        try:
            if not self._is_encrypt:
                post = [await make_event()]

            # when it's encrypt we make as many event as to_users
            else:
                post = []
                for c_post in tags:
                    if c_post[0] == 'subject':
                        continue
                    # we leave all the p_tags - should we just restrict to who we're sending too?
                    post.append(await make_event(c_post[1]))

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
    def as_signer(self) -> SignerInterface:
        return self._user_sign

    @property
    def connection_status(self):
        return self._client.connected

