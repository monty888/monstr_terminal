from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import FormattedText
from monstr.event.event import Event
from monstr.encrypt import Keys
from app.post import PostApp
from monstr.ident.profile import Profile, NIP5Helper, NIP5Error
from monstr.ident.event_handlers import ProfileEventHandler
from monstr.entities import Entities
from monstr.util import util_funcs


class EventPrinter:

    def __init__(self,
                 profile_handler: ProfileEventHandler,
                 as_user: Profile = None,
                 inbox_keys=None,
                 share_keys=None,
                 show_tags: [str] = None):

        self._profile_handler = profile_handler
        self._as_user = as_user
        self._inbox_keys = inbox_keys
        if inbox_keys is None:
            self._inbox_keys = []
        self._share_keys = share_keys
        if share_keys is None:
            self._share_keys = []

    async def print_event(self, evt: Event):
        await self.print_event_header(evt)
        await self.print_event_content(evt)

    async def _get_profile(self, key) -> Profile:
        return (await self._profile_handler.get_profiles(pub_ks=key,
                                                         create_missing=True))[0]

    async def print_event_header(self,
                           evt: Event,
                           depth=0):
        p: Profile

        ret_arr = []
        p = await self._profile_handler.get_profile(evt.pub_key,
                                                    create_missing=True)

        depth_align = ''.join(['\t'] * depth)
        ret_arr.append('%s-- %s --' % (depth_align, p.display_name()))

        # this will force fetch if needed all the profiles we need
        # so that a fetch won't be made in the next loop for each p tag
        await self._profile_handler.get_profiles(pub_ks=[pk for pk in evt.p_tags],
                                                 create_missing=True)
        to_list = []
        for c_pk in evt.p_tags:
            to_list.append((await self._profile_handler.get_profile(c_pk)).display_name())
        if to_list:
            ret_arr.append('%s-> %s' % (depth_align, to_list))

        ret_arr.append('%s%s@%s' % (depth_align, evt.id, evt.created_at))

        print('\n'.join(ret_arr))

    async def print_event_content(self, evt: Event):

        def nip_decode(the_evt: Event):
            pub_key = evt.p_tags[0]
            if pub_key == self._as_user.public_key:
                pub_key = evt.pub_key

            return evt.decrypted_content(self._as_user.private_key, pub_key)

        if evt.kind == Event.KIND_TEXT_NOTE:
            print(evt.content)
        elif evt.kind == Event.KIND_ENCRYPT:
            content = evt.content
            try:
                # basic NIP4 encrypted event from/to us
                if evt.pub_key == self._as_user.public_key or self._as_user.public_key in evt.p_tags:
                    content = nip_decode(evt)
                # clust style wrapped NIP4 event
                elif evt.pub_key in self._inbox_keys:
                    evt = PostApp.clust_unwrap_event(evt, self._as_user, self._share_keys)
                    if evt:
                        await self.print_event_header(evt, depth=1)
                        content = '\t' + nip_decode(evt)
            except:
                pass

            print(content)


class FormattedEventPrinter:

    def __init__(self,
                 profile_handler: ProfileEventHandler,
                 as_user: Profile = None,
                 inbox_keys: [Keys] =None,
                 share_keys=None,
                 show_pub_key: bool = False,
                 show_tags: [str] = None,
                 entities: bool = False,
                 nip5helper: NIP5Helper = None,
                 encrypted_kinds=None):

        self._profile_handler = profile_handler
        self._as_user = as_user

        self._inbox_map = {}
        self._inbox_view_keys = {}
        self._inbox_decode_map = {}

        k: Keys
        if inbox_keys:
            self._inbox_view_keys = {k.public_key_hex() for k in inbox_keys}
            self._inbox_decode_map = {k.public_key_hex(): k.private_key_hex() for k in inbox_keys}

        self._share_keys = share_keys

        if share_keys is None:
            self._share_keys = {}

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

    async def print_event(self, evt: Event):
        print_formatted_text(FormattedText(await self.get_event_header(evt)))
        print_formatted_text(FormattedText(await self.get_event_content(evt)))
        print_formatted_text(FormattedText(await self.get_event_footer(evt)))

    async def _get_profile(self, key) -> Profile:
        # will error if key is not valid, doesn't break anything for us but maybe we should fix?
        ret = (await self._profile_handler.get_profiles(pub_ks=key,
                                                        create_missing=True))[0]
        return ret

    def _is_user(self, key):
        return self._as_user is not None and self._as_user.public_key == key

    async def _is_contact(self, key):
        ret = False
        if self._as_user is not None:
            if not self._as_user.contacts_is_set():
                await self._profile_handler.load_contacts(self._as_user)
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
        await self._profile_handler.get_profiles(pub_ks=[pk for pk in evt.p_tags],
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
            all_tag_names = {c_tag[0] for c_tag in evt.tags}
            for c_tag_name in all_tag_names:
                txt_arr.append(('', f'\n{depth_align}'))
                txt_arr.append(('cyan', '-tags-'))
                if '*' in self._show_tags or c_tag_name in self._show_tags:

                    for c_tag_v in evt.get_tags(c_tag_name):
                        v_style = ''
                        if c_tag_name == 'p':
                            v_style = await self._get_pub_k_style(c_tag_v[0])

                        txt_arr.append(('cyan', f'\n{depth_align}{c_tag_name}'))
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

                        txt_arr.append(('', ']\n'))

        # actualy do the output if any
        return txt_arr

    async def highlight_tags(self, content: str, p_tags: [], default_style=''):
        replacements = {}
        arr_str = []
        ret = []
        for i, c_pk in enumerate(p_tags):
            tag_p: Profile = await self._get_profile(c_pk)
            replacements['#[%s]' % i] = tag_p.display_name()

        for c_word in content.split(' '):
            if c_word in replacements:
                if arr_str:
                    ret.append((default_style, ' '.join(arr_str)))
                    arr_str = []
                ret.append(('green', ' @%s ' % replacements[c_word]))
            else:
                arr_str.append(c_word)

        if arr_str:
            ret.append((default_style, ' '.join(arr_str)))

        return ret

    async def get_event_content(self, evt):

        def nip_decode(the_evt: Event):
            pub_key = the_evt.p_tags[0]
            if pub_key == self._as_user.public_key:
                pub_key = the_evt.pub_key
            return the_evt.decrypted_content(self._as_user.private_key, pub_key)

        txt_arr = []

        # by default this is just kind4, but for example you could give an empheral kind then you have empheral
        # encrypted events, obvs as much as you trusty that the relay is doing as it say...
        if evt.kind in self._encrypted_kinds:
            try:
                # basic NIP4 encrypted event from/to us
                if self._as_user and \
                        (evt.pub_key == self._as_user.public_key or
                         self._as_user.public_key in evt.p_tags):
                    txt_arr.append(('', nip_decode(evt)))
                # clust style wrapped NIP4 event
                elif evt.pub_key in self._inbox_view_keys:
                    inbox_p: Profile = await self._get_profile(key=evt.pub_key)
                    unwrapped_evt = PostApp.clust_unwrap_event(evt, self._as_user, self._share_keys, self._inbox_decode_map)
                    if unwrapped_evt:
                        # get content from unwrapped event and output inbox info
                        if unwrapped_evt.kind == Event.KIND_ENCRYPT:
                            txt_arr.append(('', f'\tencrypted evt in inbox({inbox_p.display_name()})-->'))
                            content = nip_decode(unwrapped_evt)
                        else:
                            txt_arr.append(('', '\tplaintext evt in inbox(%s)-->' % inbox_p.display_name()))
                            content = unwrapped_evt.content

                        # output unwrapped event
                        txt_arr += await self.get_event_header(unwrapped_evt, depth=1)
                        txt_arr += [('', '\n\t' + content)]
                        txt_arr += await self.get_event_footer(unwrapped_evt, depth=1)

                    else:
                        # event inbox that we should be able to decrypt but...
                        txt_arr.append(('', f'\tunable to decrypt evt in inbox({inbox_p.display_name()})-->'))
                        txt_arr.append(('gray', evt.content))

                # encrypted event that we don't have the info to decrypt
                else:
                    txt_arr.append(('gray', evt.content))

            # any exception just output raw content
            except Exception as e:
                txt_arr.append(('gray', evt.content))

        # anything other that encrypted just treated as text
        else:
            txt_arr.append(('', evt.content))

        return txt_arr

    # async def print_event_content(self, evt: Event):
    #     style = ''
    #     content, could_decode = await self._get_decode_event_content(evt)
    #     if not could_decode:
    #         style = 'gray'
    #
    #     print_formatted_text(FormattedText(await self.highlight_tags(content=content,
    #                                                                  p_tags=evt.p_tags,
    #                                                                  default_style=style)))


