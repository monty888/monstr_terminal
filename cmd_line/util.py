import asyncio

import aioconsole
import json
from abc import abstractmethod
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import FormattedText
from monstr.event.event import Event
from monstr.encrypt import Keys
from monstr.inbox import Inbox
from monstr.client.client import Client
from monstr.ident.profile import Profile, NIP5Helper, NIP5Error
from monstr.ident.event_handlers import ProfileEventHandler
from monstr.signing import SignerInterface
from monstr.entities import Entities
from monstr.util import util_funcs


class EventPrinter:

    # print the event
    @abstractmethod
    async def aprint_event(self, the_client: Client, sub_id, evt: Event):
        pass

    # any other msgs
    @abstractmethod
    async def astatus(self, status: str):
        pass


class WrappedEventPrinter(EventPrinter):
    """
        support events that have been wrapped inside a public inbox
        also adds method for getting the decrypted content of an event
    """
    def __init__(self,
                 as_sign: SignerInterface = None,
                 inboxes: [Inbox] = None,
                 # kinds to output - probably a filter would be more flexible here... None will not restrict at all
                 kinds: {int} = None,
                 # kinds that we'll be decrypted
                 encrypted_kinds: {int} = None
                 ):

        # if given will be used for decrypting
        self._as_sign = as_sign

        self._inboxes = inboxes
        # lookups for dealing with inboxes
        c_i: Inbox
        self._inbox_view_keys = {}
        self._inbox_decode_map = {}

        asyncio.create_task(self._ready_inboxes())

        self._kinds = kinds

        self._encrypted_kinds = {}
        # by default nothing will be decrypted - probably at least want to set as {Event.KIND_ENCRYPT}
        if encrypted_kinds is not None:
            self._encrypted_kinds = encrypted_kinds

        self._ready = False

    async def wait_ready(self):
        while not self._ready:
            await asyncio.sleep(0.1)

    async def _ready_inboxes(self):
        # lookups for dealing with inboxes
        if self._inboxes:
            c_i: Inbox
            self._inbox_view_keys = {await c_i.pub_key for c_i in self._inboxes}
            self._inbox_decode_map = {await c_i.pub_key: c_i for c_i in self._inboxes}
        self._ready = True

    def event_needs_unwrap(self, evt: Event) -> bool:
        return evt.pub_key in self._inbox_view_keys

    async def get_unwrapped_event(self, evt) -> Event:
        """
        unwraps evt, if unable you just get the orignal event back
        if you need to know that you have an event that needed unwrapping and it failed you can check

        if event_needs_unwrap(evt) is True and evt.id == ret.id then we failed to unwrap an event that needed unwrap

        :param evt:
        :return:
        """

        ret = evt
        if self.event_needs_unwrap(evt):
            unwrapped_evt = await self._inbox_decode_map[evt.pub_key].unwrap_event(evt=evt,
                                                                                   user_sign=self._as_sign)
            if unwrapped_evt:
                ret = unwrapped_evt

        return ret

    def event_needs_decrypt(self, evt: Event) -> bool:
        # if we've been given a signer and the event is in kinds we have been told are encrypted
        # we'll attempt to decrypt it with _as_sign
        return self._as_sign and evt.kind in self._encrypted_kinds

    async def get_decrypted_event(self, evt: Event) -> Event:
        """
        decrypts evt, if unable you just get the orignal event back
        checking failed to decrypt works same as unwrap except you need to compare the event content
        :param evt:
        :return:
        """
        # copy the event so we're working on a new obj
        ret = Event.load(evt.data())

        if self.event_needs_decrypt(evt):
            # for the public key we'll try all p_tags and the events public key with
            # are priv key, so we have a chance to decrypt non standard events also
            # we just exit first time we don't cause exception
            # (Like we produce from poster)
            for c_p_tag in [evt.pub_key] + evt.p_tags:
                try:
                    ret.content = await self._as_sign.nip4_decrypt(payload=ret.content,
                                                                   for_pub_k=c_p_tag)

                    # if we got here then we manage to decrypt so exit
                    break
                except Exception as e:
                    pass

        return ret

    # will we output the event? This probably is mainly useful if dealing with wrapped events
    # where we may want to check again that they pass some filter after unwrapping
    def output_event(self, evt: Event) -> bool:
        return self._kinds is None or evt.kind in self._kinds

    # print the event
    async def aprint_event(self, the_client: Client, sub_id, evt: Event):
        # you probably want to override this
        aioconsole.aprint(await self.get_unwrapped_event(evt))

    # any other msgs
    @abstractmethod
    async def astatus(self, status: str):
        return


class JSONPrinter(WrappedEventPrinter):

    def __init__(self,
                 as_sign: SignerInterface = None,
                 inboxes: [Inbox] = None,
                 kinds=None,
                 encrypted_kinds: set = None
                 ):

        super().__init__(as_sign=as_sign,
                         inboxes=inboxes,
                         kinds=kinds,
                         encrypted_kinds=encrypted_kinds)

    # outputs event in raw format
    async def aprint_event(self, the_client: Client, sub_id, evt: Event):
        # unwrap and decrypt event as required - if unable or uneeded left as is
        evt = await self.get_unwrapped_event(evt)
        if self.output_event(evt):
            evt = await self.get_decrypted_event(evt)
            await aioconsole.aprint(json.dumps(evt.event_data()))

    async def astatus(self, status: str):
        return


class ContentPrinter(WrappedEventPrinter):

    def __init__(self,
                 as_sign:SignerInterface = None,
                 inboxes: [Inbox] = None,
                 kinds=None,
                 encrypted_kinds: set = None
                 ):

        super().__init__(as_sign=as_sign,
                         inboxes=inboxes,
                         kinds=kinds,
                         encrypted_kinds=encrypted_kinds)

    # output just the content of an event
    async def aprint_event(self, the_client: Client, sub_id, evt: Event):
        # unwrap and decrypt event as required - if unable or uneeded left as is
        evt = await self.get_unwrapped_event(evt)
        if self.output_event(evt):
            evt = await self.get_decrypted_event(evt)
            content = evt.content
            await aioconsole.aprint(content)

    async def astatus(self, status: str):
        await aioconsole.aprint(status)


class FormattedEventPrinter(WrappedEventPrinter):

    def __init__(self,
                 profile_handler: ProfileEventHandler,
                 as_user: Profile = None,
                 as_sign: SignerInterface = None,
                 inboxes: [Inbox] = None,
                 show_pub_key: bool = False,
                 show_tags: [str] = None,
                 entities: bool = False,
                 nip5helper: NIP5Helper = None,
                 kinds=None,
                 encrypted_kinds=None):

        self._profile_handler = profile_handler

        self._as_user = as_user

        # styles for colouring user output
        # us
        self._as_user_style = 'bold ForestGreen'
        # someone we follow
        self._as_user_contact_style = 'ForestGreen'
        # anyone else
        self._as_user_non_contact_style = 'FireBrick bold'

        # output npub, note instead of hex for event_id and pks
        self._entities = entities

        # at end show pubkey
        self._show_pub_key = show_pub_key
        # output these tags or all if ['*']
        self._show_tags = show_tags
        if self._show_tags:
            self._show_tags = set(self._show_tags)

        # if supplied then any nip5s will be checked and colored green if good
        self._nip5helper = nip5helper
        # styles used when checking nip5s
        self._nip5_valid_style = 'ForestGreen'
        self._nip5_invalid_style = 'FireBrick bold'

        # events that we expect to be encrypted
        self._encrypted_kinds = encrypted_kinds
        if self._encrypted_kinds is None:
            self._encrypted_kinds = {Event.KIND_ENCRYPT}

        super().__init__(as_sign=as_sign,
                         inboxes=inboxes,
                         kinds=kinds,
                         encrypted_kinds=encrypted_kinds)

    async def aprint_event(self, the_client: Client, sub_id, evt: Event):
        unwrapped_evt = evt
        if self.event_needs_unwrap(evt):
            unwrapped_evt = await self.get_unwrapped_event(evt)

        if self.output_event(unwrapped_evt):
            print_formatted_text(FormattedText(await self.get_event_header(evt)))
            print_formatted_text(FormattedText(await self.get_event_content(evt, unwrapped_evt)))
            print_formatted_text(FormattedText(await self.get_event_footer(evt)))

    async def astatus(self, status: str):
        # anything thats not the event
        await aioconsole.aprint(status)

    async def _get_profile(self, key) -> Profile:
        # will error if key is not valid, doesn't break anything for us but maybe we should fix?
        ret = (await self._profile_handler.aget_profiles(pub_ks=key,
                                                         create_missing=True))[0]
        return ret

    def _is_user(self, key):
        return self._as_user is not None and self._as_user.public_key == key

    async def _is_contact(self, key):
        ret = False
        if self._as_user is not None:
            if not self._as_user.contacts_is_set():
                await self._profile_handler.aload_contacts(self._as_user)
            ret = key in self._as_user.contacts.follow_keys()

        return ret

    async def _get_pub_k_style(self, pub_k):
        ret = ''
        # no styling if no as_user
        if self._as_user:
            if self._is_user(pub_k):
                ret = self._as_user_style
            elif await self._is_contact(pub_k):
                ret = self._as_user_contact_style
            else:
                ret = self._as_user_non_contact_style

        return ret

    async def get_event_header(self,
                                     evt: Event,
                                     depth=0) -> []:
        p: Profile

        txt_arr = []
        depth_align = ''.join(['\t'] * depth)
        txt_arr.append(('', '\n%s--- ' % depth_align))
        create_p = await self._get_profile(evt.pub_key)

        style = await self._get_pub_k_style(evt.pub_key)

        name = create_p.name

        nip05_domain = None
        name_nip05match = False

        if create_p.nip05:
            nip05_split = create_p.nip05.split('@')
            if len(nip05_split) > 1:
                nip05_name = nip05_split[0]
                nip05_domain = nip05_split[1]
                if name is None and nip05_domain:
                    name = nip05_name
                name_nip05match = name.lower() == nip05_name.lower() or nip05_name == '_'

        if name is None or name.replace(' ', '') == '':
            name = util_funcs.str_tails(create_p.public_key)

        txt_arr.append((style, name))

        # nip5 info if any
        if create_p.nip05:
            nip5_style = ''

            if self._nip5helper:
                nip5_style = self._nip5_invalid_style
                try:
                    if await self._nip5helper.is_valid(create_p.nip05, create_p.public_key):
                        nip5_style = self._nip5_valid_style
                except NIP5Error as ne:
                    pass

            if name_nip05match:
                txt_arr.append((nip5_style, f'@{nip05_domain}'))
            else:
                txt_arr.append((nip5_style, f' ({create_p.nip05})'))


        txt_arr.append(('', ' ---'))

        to_list = []
        sep = False

        # this will force fetch if needed all the profiles we need
        # so that a fetch won't be made in the next loop for each p tag
        await self._profile_handler.aget_profiles(pub_ks=[pk for pk in evt.p_tags],
                                                 create_missing=True)

        for c_pk in evt.p_tags:
            style = await self._get_pub_k_style(c_pk)

            to_p = await self._get_profile(c_pk)
            if sep:
                to_list.append(('', ', '))

            to_list.append((style, to_p.display_name()))

            sep = True

        if to_list:
            txt_arr.append(('', '\n%s-> ' % depth_align, ))
            txt_arr = txt_arr + to_list

        subject_tags = evt.get_tags_value('subject')
        if subject_tags:
            txt_arr.append(('', '\n%s' % depth_align))
            txt_arr.append(('', '[subject - %s]' % ','.join(subject_tags)))

        txt_arr.append(('','\n%s' % depth_align))

        id = evt.id
        if self._entities:
            id = Entities.encode('note', id)

        txt_arr.append(('cyan', id))
        txt_arr.append(('','@'))
        txt_arr.append(('', '%s' % evt.created_at))

        # extra kind specific header
        if evt.kind == Event.KIND_CHANNEL_MESSAGE and evt.e_tags:
            txt_arr.append(('', f'\nchannel: {evt.e_tags[0]}'))

        return txt_arr

    async def get_event_footer(self,
                               evt: Event,
                               depth=0):

        txt_arr = []
        depth_align = ''.join(['\t'] * depth)

        if self._show_pub_key:
            txt_arr.append(('', f'\n{depth_align}'))
            txt_arr.append(('cyan', '-pubkey-\n'))
            out_pk = evt.pub_key
            if self._entities:
                out_pk = Entities.encode('npub', out_pk)
            txt_arr.append(('', depth_align))
            txt_arr.append((await self._get_pub_k_style(evt.pub_key), f'{out_pk}'))

        if self._show_tags:
            txt_arr.append(('', f'\n{depth_align}'))
            txt_arr.append(('cyan', f'-tags-'))

            all_tag_names = list(evt.tags.tag_names)
            all_tag_names.sort()

            for c_tag_name in all_tag_names:

                if '*' in self._show_tags or c_tag_name in self._show_tags:
                    # tag header
                    txt_arr.append(('cyan', f'\n{depth_align}{c_tag_name}'))

                    # now output values
                    for c_tag_v in evt.get_tags(c_tag_name):
                        v_style = ''
                        if c_tag_name == 'p':
                            v_style = await self._get_pub_k_style(c_tag_v[0])

                        txt_arr.append(('', f'\n{depth_align}['))
                        sep = ''
                        for i, item in enumerate(c_tag_v):
                            item_val = item
                            if self._entities:
                                try:
                                    if c_tag_name == 'p':
                                        item_val = Entities.encode('npub', item_val)
                                    elif c_tag_name == 'e':
                                        item_val = Entities.encode('note', item_val)

                                # invalid data prob?
                                except Exception as e:
                                    pass
                            if c_tag_name == 'p' and i == 0:
                                txt_arr.append((v_style, f'{item_val}'))
                            else:
                                txt_arr.append(('', f'{sep}{item_val}'))
                            sep = ','

                        txt_arr.append(('', ']'))

        # actualy do the output if any
        return txt_arr

    async def highlight_tags(self, evt: Event, default_style='', depth=0):
        replacements = {}
        arr_str = []
        ret = []
        p: Profile
        depth_align = ''.join(['\t'] * depth)

        # map tag replacements, only p tag currently
        # note this is for #[n] style to tags
        # there is also nostr:npub, etc.. maybe that is the new way? should be easy to add also...
        for i, tag_vals in enumerate(evt.tags):
            # def replacement is just grayed of the #[n] text
            r_v = {
                'text': f'#[{i}]',
                'style': 'gray'
            }

            if len(tag_vals) > 1:
                t_n = tag_vals[0]
                t_v = tag_vals[1]
                # we only do p replacements
                if t_n == 'p':
                    if Keys.is_valid_key(t_v):
                        p = await self._get_profile(t_v)

                        r_v = {
                            'text': p.display_name(),
                            'style': await self._get_pub_k_style(t_v)
                        }

                        # add replacements for npub and nostr:npub
                        if p.name:
                            npub = Entities.encode('npub', p.public_key)
                            replacements[f'nostr:{npub}'] = {
                                'text': f' {p.display_name()} ',
                                'style': await self._get_pub_k_style(t_v)
                            }

                replacements[f'#[{i}]'] = r_v

        for c_line in evt.content.splitlines():
            # ret.append(('', '\n'))
            ret.append(('', '\n'+depth_align))
            for c_word in c_line.split(' '):
                if c_word in replacements:
                    if arr_str:
                        ret.append((default_style, ' '.join(arr_str)))
                        arr_str = []

                    # TODO: cols should be based on if we follow
                    replacement = replacements[c_word]
                    ret.append((replacement['style'], replacement['text']))
                else:
                    arr_str.append(c_word)

            if arr_str:
                ret.append((default_style, ' '.join(arr_str)))
                arr_str = []

        return ret

    async def get_event_content(self, evt, unwrapped_evt):
        txt_arr = []
        print_depth = 0
        print_style = 'gray'
        decrypted_evt = await self.get_decrypted_event(unwrapped_evt)
        print_evt = evt
        content_done = False

        # FIXME - works but this logic is pretty crazy
        if self.event_needs_unwrap(evt):
            inbox_p: Profile = await self._get_profile(key=evt.pub_key)
            if evt.id != unwrapped_evt.id:
                print_depth = 1
                if self.event_needs_decrypt(unwrapped_evt):
                    txt_arr.append(('', f'\tencrypted evt in inbox({inbox_p.display_name()})-->'))
                    print_evt = decrypted_evt
                    if decrypted_evt.content != unwrapped_evt.content:
                        print_style = ''

                else:
                    txt_arr.append(('', '\tplaintext evt in inbox(%s)-->' % inbox_p.display_name()))
                    print_style = ''
                    print_evt = unwrapped_evt

                txt_arr += await self.get_event_header(print_evt, depth=print_depth)
                txt_arr += await self.highlight_tags(evt=print_evt,
                                                     default_style=print_style,
                                                     depth=print_depth)
                txt_arr += await self.get_event_footer(evt=print_evt,
                                                       depth=1)
                content_done = True

            else:
                txt_arr.append(('', f'\tunable to decrypt evt in inbox({inbox_p.display_name()})-->'))

        # basic events not via inbox
        else:
            if self.event_needs_decrypt(evt):
                print_evt = decrypted_evt
                if decrypted_evt.content != evt.content:
                    print_style = ''
            else:
                print_style = ''

        if not content_done:
            txt_arr += await self.highlight_tags(evt=print_evt,
                                                 default_style=print_style,
                                                 depth=print_depth)

        return txt_arr




