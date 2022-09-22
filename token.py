# token - A maubot plugin to manage your synapse registration tokens
# Copyright (C) 2022 Michael Auer
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from mautrix.types import EventType
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper
from maubot import Plugin, MessageEvent
from maubot.handlers import event, command

import json
import time
import datetime
import requests
from typing import Type

error_msg_no_auth="My mom said I'm not allowed to talk to strangers."

class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("access_token")
        helper.copy("base_command")
        helper.copy("whitelist")
        helper.copy("admin_api")
        helper.copy("default_uses_allowed")
        helper.copy("default_expiry_time")

def get_token(base_url,access_token,tokenID):
    url = base_url + '/v1/registration_tokens'
    if tokenID:
        url+="/{}".format(tokenID)
    payload = '{}'
    headers = {'content-type': 'application/json', 'Authorization': 'Bearer {}'.format(access_token)}
    r = requests.get(url, data=payload, headers=headers)
    if (r.status_code != 200):
        return False, "ERROR: {}".format(r.status_code)
    return True, r.json()

def gen_token(base_url,access_token,uses_allowed,expiry_time):
    url = base_url + '/v1/registration_tokens/new'
    payload = {}
    if uses_allowed:
        payload["uses_allowed"]=uses_allowed
    if expiry_time:
        payload["expiry_time"]=expiry_time
    headers = {'content-type': 'application/json', 'Authorization': 'Bearer {}'.format(access_token)}
    r = requests.post(url, data=json.dumps(payload), headers=headers)
    if (r.status_code != 200):
        return False, "ERROR: {}".format(r.status_code)
    return True, r.json()

def del_token(base_url,access_token,tokenID):
    url = base_url + '/v1/registration_tokens/{}'.format(tokenID)
    payload = '{}'
    headers = {'content-type': 'application/json', 'Authorization': 'Bearer {}'.format(access_token)}
    r = requests.delete(url, data=payload, headers=headers)
    if (r.status_code != 200):
        return False, "ERROR: {}".format(r.status_code)
    return True, ""

def parse_single_token(token):
    expiry_time=token["expiry_time"]
    if expiry_time:
        expiry_time=datetime.datetime.fromtimestamp(expiry_time/1000.0)
    return "**{}**\n- uses_allowed: {}\n- pending: {}\n- completed: {}\n- expiry_time: {}\n".format(token["token"],token["uses_allowed"],token["pending"],token["completed"],expiry_time)

def parse_tokens(json):
    valid_tokens="\u2705 Valid Tokens \u2705\n"
    invalid_tokens="\u274C Invalid Tokens \u274C\n"
    for token in json["registration_tokens"]:
        valid=True
        if token["uses_allowed"]:
            valid = valid and token["completed"]<token["uses_allowed"]
        if token["expiry_time"]:
            valid = valid and token["expiry_time"]>int(time.time())*1000
        if valid:
            valid_tokens+="- {}\n".format(token["token"])
        else:
            invalid_tokens+="- {}\n".format(token["token"])
    return invalid_tokens + "\n" + valid_tokens

class TokenBot(Plugin):
    def authenticate(self, user):
        if user in self.config["whitelist"]:
            return True
        return False

    @classmethod
    def get_config_class(cls) -> Type[BaseProxyConfig]:
        return Config

    async def start(self) -> None:
        self.config.load_and_update()

    @command.new(name=lambda self: self.config["base_command"], help="List available Tokens", require_subcommand=True)
    async def token(self, event: MessageEvent) -> None:
        pass

    @token.subcommand(name="list", help="List all [or specific] Tokens")
    @command.argument("token", required=False, pass_raw=True)
    async def list_tokens(self, event: MessageEvent, token: str) -> None:
        if not self.authenticate(event.sender):
            await event.reply(error_msg_no_auth)
            return
        ret, available_token=get_token(self.config["admin_api"],self.config["access_token"],token)
        msg=""
        if ret:
            if token:
                msg=parse_single_token(available_token)
            else:
                msg=parse_tokens(available_token)
        else:
            msg=available_token
        await event.reply(msg)

    @token.subcommand(name="generate", help="Generate a Token")
    @command.argument("uses",parser=lambda val: int(val) if val else None, required=False)
    @command.argument("expiry",parser=lambda val: int(val) if val else None, required=False)
    async def generate_token(self, event: MessageEvent, uses: int, expiry: int) -> None:
        if not self.authenticate(event.sender):
            await event.reply(error_msg_no_auth)
            return
        if not uses:
            uses=self.config["default_uses_allowed"]
        elif uses <= 0:
            uses = None
        if not expiry:
            expiry=self.config["default_expiry_time"]
        if expiry <= 0:
            expiry = None
        else:
            expiry = expiry*1000 + int(time.time())*1000
        ret, available_token=gen_token(self.config["admin_api"],self.config["access_token"],uses,expiry)
        msg=""
        if ret:
            msg=parse_single_token(available_token)
        else:
            msg=available_token
        await event.reply(msg)

    @token.subcommand(name="delete", help="Delete a Token")
    @command.argument("token", required=True, pass_raw=True)
    async def delete_token(self, event: MessageEvent, token: str) -> None:
        if not self.authenticate(event.sender):
            await event.reply(error_msg_no_auth)
            return
        ret, available_token=del_token(self.config["admin_api"],self.config["access_token"],token)
        msg="Token deleted!"
        if not ret:
            msg=available_token
        await event.reply(msg)       

    #@token.subcommand(name="test", help="Delete a Token")
    #async def delete_token(self, event: MessageEvent) -> None:
    #    await event.reply("{}".format(event.sender))
