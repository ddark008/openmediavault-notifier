import json
import unittest
from pathlib import Path

from omvnotifier import mtproto


class FakeTDLib:
    def __init__(self, proxy_enabled=True, delivery_type="updateMessageSendSucceeded"):
        self.requests = []
        self.updates = []
        self.proxy_enabled = proxy_enabled
        self.delivery_type = delivery_type
        self.queued_replies = []

    def send(self, request):
        self.requests.append(request)
        method = request["@type"]
        updates = {
            "setNetworkType": [{"@type": "ok"}],
            "addProxy": [{"@type": "addedProxy", "is_enabled": self.proxy_enabled}],
            "setTdlibParameters": [
                {"@type": "ok"},
                {"@type": "updateAuthorizationState",
                 "authorization_state": {"@type": "authorizationStateWaitPhoneNumber"}},
            ],
            "checkAuthenticationBotToken": [
                {"@type": "ok"},
                {"@type": "updateAuthorizationState",
                 "authorization_state": {"@type": "authorizationStateReady"}},
            ],
            "createPrivateChat": [{"@type": "chat", "id": 42,
                                   "permissions": {"can_send_basic_messages": False}}],
            "getChat": [{"@type": "chat", "id": 42,
                         "permissions": {"can_send_basic_messages": True}}],
            "sendMessage": [
                {"@type": self.delivery_type, "old_message_id": 100},
                {"@type": "message", "id": 100, "sending_state": {"@type": "messageSendingStatePending"}},
            ],
        }[method]
        if method == "sendMessage" and not any(item["@type"] == "getChat" for item in self.requests):
            updates = [{"@type": "error", "code": 400,
                        "message": "Not enough rights to send text messages to the chat"}]
        response = next(update for update in updates if not update["@type"].startswith("update"))
        response["@extra"] = request["@extra"]
        if method == "addProxy" or request["@extra"] == "offline":
            self.queued_replies.append(response)
            return
        self.updates.extend(updates)
        if method == "setTdlibParameters":
            self.updates.extend(self.queued_replies)

    def receive(self):
        return self.updates.pop(0)


class MTProtoTest(unittest.TestCase):
    request = {
        "api_id": 123456, "api_hash": "a" * 32, "bot_token": "123:abc",
        "chat_id": "42", "text": "NAS notification",
        "proxy": {"server": "proxy.example", "port": 443, "secret": "dd" + "b" * 32},
    }

    def test_send_waits_for_login_and_delivery_confirmation(self):
        td = FakeTDLib()
        mtproto.send(td, self.request, Path("/var/lib/notifier-test"))
        self.assertEqual([request["@type"] for request in td.requests], [
            "setNetworkType", "addProxy", "setTdlibParameters", "setNetworkType",
            "checkAuthenticationBotToken", "createPrivateChat", "getChat", "sendMessage",
        ])
        self.assertTrue(td.requests[1]["enable"])
        self.assertEqual(td.requests[-1]["chat_id"], 42)
        self.assertEqual(td.requests[-1]["input_message_content"]["text"]["text"], "NAS notification")

    def test_disabled_proxy_fails_before_bot_login(self):
        td = FakeTDLib(proxy_enabled=False)
        with self.assertRaisesRegex(mtproto.MTProtoError, "^proxy$"):
            mtproto.send(td, self.request, Path("/var/lib/notifier-test"))
        self.assertEqual([request["@type"] for request in td.requests], [
            "setNetworkType", "addProxy", "setTdlibParameters",
        ])

    def test_rejected_message_is_not_a_success(self):
        td = FakeTDLib(delivery_type="updateMessageSendFailed")
        with self.assertRaisesRegex(mtproto.MTProtoError, "^send$"):
            mtproto.send(td, self.request, Path("/var/lib/notifier-test"))

    def test_invalid_proxy_link_does_not_disclose_secret(self):
        secret = "test-secret"
        with self.assertRaisesRegex(mtproto.MTProtoError, "^Invalid Telegram MTProxy share link$"):
            mtproto.parse_proxy(f"tg://proxy?server=proxy.example&port=70000&secret={secret}")

    def test_omv_channel_models_agree_on_mtproxy_fields(self):
        models = Path(__file__).parents[1] / "usr/share/openmediavault/datamodels"
        parent = json.loads((models / "conf.service.notifier.json").read_text())
        child = json.loads((models / "conf.service.notifier.channel.json").read_text())
        nested = parent["properties"]["channels"]["properties"]["channel"]["items"]["properties"]
        for field in ("mtproxy", "apiid", "apihash"):
            self.assertEqual(nested.get(field), child["properties"][field])
