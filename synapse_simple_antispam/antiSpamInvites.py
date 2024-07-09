from synapse.spam_checker_api import RegistrationBehaviour
import logging
from typing import Dict, Union, Optional
from synapse.module_api import ModuleApi
from synapse.module_api.errors import Codes
from synapse import module_api
import re
import json

class AntiSpamInvites(object):
    def __init__(self, config, api):
        self.config = self.parse_config(config)
        self.api = api
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.groups = {}
        self.groups = self.config['groups']
        self.logger.info("[ANTISPAM] ******ANTISPAM initiated***********")
        for key, value in self.groups.items():
            self.logger.info(f"{key}: {value}")

    @staticmethod
    def parse_config(config):
        return json.loads(config)
        
    def check_event_for_spam(self, foo):
        return False  # allow all events
    
    async def user_may_join_room(self, inviter_user_id, room_id, is_invited):
        try:
            my_room_states = await self.api.get_room_state(room_id, None)
            members = [state_key for event_type, state_key in my_room_states.keys() if event_type == 'm.room.member']
            members = [member_id for member_id in members if self.remove_left_users(member_id, my_room_states)]
            self.logger.info("[ANTISPAM] user_may_join_room Room members: {}".format(members))  # Log the room members
        except Exception as e:
            self.logger.error("[ANTISPAM] user_may_join_room Exception  {}: {}".format(member_id, e))
            return module_api.NOT_SPAM
        # Loop through members, excluding inviter_user_id
        for member_id in members:
            if member_id != inviter_user_id:
                # Check if each member is allowed
                if not self.checkif_users_allowed(member_id, inviter_user_id):
                    self.logger.info("[ANTISPAM] user_may_join_room Not allowed inviter_user_id={}, room_id={}".format(inviter_user_id, room_id))            
                    return Codes.FORBIDDEN

        return module_api.NOT_SPAM

    async def user_may_invite(self, inviter_user_id, invitee_user_id, room_id):
       
        # Check if inviter_user_id is allowed
        if not self.checkif_users_allowed(inviter_user_id, invitee_user_id):
            self.logger.info("[ANTISPAM] user_may_invite: inviter_user_id={}, invitee_user_id={}".format(inviter_user_id, invitee_user_id))            
            return False
        try:
            my_room_states = await self.api.get_room_state(room_id, None)
            members = [state_key for event_type, state_key in my_room_states.keys() if event_type == 'm.room.member']
            members = [member_id for member_id in members if self.remove_left_users(member_id, my_room_states)]
            self.logger.info("[ANTISPAM] user_may_invite room members: {}".format(members))  # Log the room members
        except Exception as e:
            self.logger.error("[ANTISPAM] user_may_invite Execption memberID {}: error {}".format(member_id, e))

        # Loop through members, excluding inviter_user_id
        for member_id in members:
            if member_id != inviter_user_id:
                # Check if each member is allowed
                if not self.checkif_users_allowed(member_id, invitee_user_id):
                    self.logger.info("[ANTISPAM] user_may_invite inviter_user_id={}, invitee_user_id={}".format(inviter_user_id, invitee_user_id))            
                    return False

        return True
    
    def remove_left_users(self, member_id, room_states):
        try:
            member_state = room_states.get(('m.room.member', member_id))

            if member_state and hasattr(member_state, 'membership'):
                membership = member_state.membership
                return membership != 'leave'
        except KeyError:
                self.logger.info("[ANTISPAM] remove_left_users exception invitee_user_id={}".format(member_id))            
                return True
        return True
        
    def user_may_create_room(self, userid):
        return True  # allow all room creations

    def user_may_create_room_alias(self, userid, room_alias):
        return True  # allow all room aliases

    def user_may_publish_room(self, userid, room_id):
        return True  # allow publishing of all rooms

    def check_username_for_spam(self, user_profile):
        searcher_id = None
        user_id = None
        searcher_id = user_profile["searcher_id"]
        user_id = user_profile["user_id"]

        self.logger.info("[ANTISPAM] **** check_username_for_spam searchid==>={}".format(searcher_id))            

        if searcher_id is not None and  user_id is not None:
            mark_as_spam = not self.checkif_users_allowed(searcher_id, user_id)
            if mark_as_spam:
                return mark_as_spam
        return False  # allow all usernames

    def check_registration_for_spam(
        self,
        email_threepid,
        username,
        request_info,
        auth_provider_id,
    ):
        return RegistrationBehaviour.ALLOW  # allow all registrations

    def check_media_file_for_spam(self, file_wrapper, file_info):
        return False  # allow all media
        
    def checkif_users_allowed(self, inviter_user_id, invitee_user_id):
        if inviter_user_id is None or invitee_user_id is None:
            return False

        inviter_groups = self.find_user_groups(inviter_user_id, "Normal", "Restricted")
        invitee_groups = self.find_user_groups(invitee_user_id, "Normal", "Restricted")

        # Iterate over all possible group combinations for inviter and invitee
        for inviter_group in inviter_groups:
            for invitee_group in invitee_groups:
                # If inviter and invitee belong to the same group
                if inviter_group == invitee_group:
                    if self.is_normal_user(inviter_user_id, inviter_group):
                        return True
                    elif self.is_restricted_user(inviter_user_id, inviter_group):
                        if self.is_within_group_allowed(inviter_group):
                            return True
                        else:
                            return self.is_normal_user(invitee_user_id, inviter_group)
                # If inviter and invitee belong to different groups
                else:
                    if self.is_normal_user(inviter_user_id, inviter_group) and self.is_normal_user(invitee_user_id, invitee_group):
                        return True

        return False


    def find_user_groups(self, user_id, *roles):
        groups = []
        for group, roles_dict in self.groups.items():
            if roles_dict is None:
                continue

            for role in roles:
                users = roles_dict.get(role, [])
                if users is not None and user_id in users:
                    groups.append(group)

            # Return ["Normal"] if user is not found in any other groups
        if not groups:
            groups.append("GeneralPublic")
        return groups

    def is_normal_user(self, user_id, group):
        if group == "GeneralPublic":
            return True
        
        normal_users = self.groups[group].get("Normal")
        if normal_users is not None:
            return user_id in normal_users
        return False


    def is_restricted_user(self, user_id, group):
        if group == "GeneralPublic":
            return False
        
        restricted_users = self.groups[group].get("Restricted")
        if restricted_users is not None:
            return user_id in restricted_users
        return False
    
    def is_within_group_allowed(self, group):
        if group == "GeneralPublic":
            return True
        
        return self.groups[group].get("allow_within_group", False)
    

class AntiSpamInvitesModule(ModuleApi):
    def __init__(self, config, api):
        
        self.antispam = AntiSpamInvites(config, api)
        self.antispam.api.register_spam_checker_callbacks(
            user_may_invite=self.user_may_invite,
            check_username_for_spam=self.check_username_for_spam,
            user_may_join_room=self.user_may_join_room,
        )
    
    async def user_may_join_room(self, user_id: str, room_id: str, is_invited: bool) -> Union[module_api.NOT_SPAM, Codes, bool]:
        return await self.antispam.user_may_join_room(user_id, room_id, is_invited)
    
    async def user_may_invite(
        self, inviter_user_id: str, invitee_user_id: str, room_id: str
    ) -> bool:
        
        return await self.antispam.user_may_invite(inviter_user_id, invitee_user_id, room_id)
    
    async def check_username_for_spam(self, user_profile: module_api.UserProfile) -> bool:
        return self.antispam.check_username_for_spam(user_profile)
    
