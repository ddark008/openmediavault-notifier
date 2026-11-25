import base64
import binascii
import fcntl
import hashlib
import importlib.resources
import ipaddress
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


PYTHON = "/opt/openmediavault-notifier-mtproxy/bin/python3"
STATE_DIRECTORY = Path("/var/lib/openmediavault-notifier")
TIMEOUT = 30
ERRORS = {
    "proxy": "TDLib could not enable the configured Telegram MTProxy",
    "login": "Telegram MTProxy login failed; check the application credentials and bot token",
    "chat": "Telegram chat is unavailable; start the bot or grant it access to the chat",
    "send": "Telegram did not confirm message delivery",
}


class MTProtoError(RuntimeError):
    pass


def deliver(channel, text):
    proxy = parse_proxy(channel.mtproxy)
    if (not re.fullmatch(r"[0-9]{1,10}", channel.apiid) or not 0 < int(channel.apiid) < 2**31
            or not re.fullmatch(r"[0-9a-fA-F]{32}", channel.apihash)):
        raise MTProtoError("Telegram MTProxy requires a valid API ID and API hash")
    if (not re.fullmatch(r"@[A-Za-z0-9_]{1,32}", channel.chatid)
            and (not re.fullmatch(r"-?[0-9]{1,16}", channel.chatid)
                 or not 0 < abs(int(channel.chatid)) < 2**53)):
        raise MTProtoError("Telegram MTProxy requires a numeric chat ID or @username")
    request = {
        "api_id": int(channel.apiid), "api_hash": channel.apihash, "bot_token": channel.token,
        "chat_id": channel.chatid, "proxy": proxy, "text": text,
    }
    # Short-lived dispatches share one session per bot, and a stalled TDLib must not stall Postfix.
    try:
        result = subprocess.run(
            [PYTHON, "-I", __file__], input=json.dumps(request), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=TIMEOUT, check=False,
        )
    except FileNotFoundError:
        raise MTProtoError("Telegram MTProxy runtime is missing; see the plugin README") from None
    except subprocess.TimeoutExpired:
        raise MTProtoError("Telegram MTProxy delivery timed out") from None
    except OSError:
        raise MTProtoError("Could not start the Telegram MTProxy runtime") from None
    if result.returncode:
        raise MTProtoError(ERRORS.get(result.stdout.strip(), "Telegram MTProxy runtime failed"))


def parse_proxy(link):
    try:
        if len(link) > 1024:
            raise ValueError
        url = urlsplit(link)
        if (url.scheme, url.netloc, url.path) not in (
            ("https", "t.me", "/proxy"), ("tg", "proxy", ""),
        ) or url.fragment:
            raise ValueError
        fields = parse_qs(url.query, strict_parsing=True, max_num_fields=3)
        if fields.keys() != {"server", "port", "secret"}:
            raise ValueError
        server, = fields["server"]
        port, = fields["port"]
        secret, = fields["secret"]
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", server):
            server = str(ipaddress.IPv6Address(server.removeprefix("[").removesuffix("]")))
        if not re.fullmatch(r"[0-9]{1,5}", port) or not 0 < int(port) <= 65535:
            raise ValueError
        if re.fullmatch(r"[0-9a-fA-F]+", secret) and len(secret) % 2 == 0:
            raw = bytes.fromhex(secret)
        else:
            if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", secret) or len(secret) > 512:
                raise ValueError
            raw = base64.b64decode(secret + "=" * (-len(secret) % 4), altchars=b"-_", validate=True)
        if not (len(raw) == 16 or len(raw) == 17 and raw[0] == 0xdd
                or 18 <= len(raw) <= 270 and raw[0] == 0xee):
            raise ValueError
    except (ValueError, binascii.Error):
        raise MTProtoError("Invalid Telegram MTProxy share link") from None
    return {"server": server, "port": int(port), "secret": raw.hex()}


def send(td, request, directory):
    deadline = time.monotonic() + TIMEOUT - 4
    authorization = ""
    replies = {}
    delivery_updates = {}

    def receive():
        nonlocal authorization
        if time.monotonic() >= deadline:
            raise TimeoutError
        event = td.receive() or {}
        kind = event.get("@type")
        if kind == "updateAuthorizationState":
            authorization = event["authorization_state"]["@type"]
        if kind in ("updateMessageSendSucceeded", "updateMessageSendFailed"):
            delivery_updates[event["old_message_id"]] = kind
        if "@extra" in event:
            replies[event["@extra"]] = event

    def wait(request_id):
        while request_id not in replies:
            receive()
        event = replies.pop(request_id)
        if event.get("@type") == "error":
            raise MTProtoError(stage)
        return event

    def call(method, **params):
        td.send({"@type": method, "@extra": method, **params})
        return wait(method)

    stage = "proxy"
    try:
        proxy = request["proxy"]
        encryption_key = hashlib.sha256(b"omv-notifier-tdlib:" + request["bot_token"].encode()).digest()
        # TDLib queues the proxy and network settings until setTdlibParameters.
        td.send({"@type": "setNetworkType", "@extra": "offline",
                 "type": {"@type": "networkTypeNone"}})
        td.send({"@type": "addProxy", "@extra": "addProxy", "enable": True, "proxy": {
            "@type": "proxy", "server": proxy["server"], "port": proxy["port"],
            "type": {"@type": "proxyTypeMtproto", "secret": proxy["secret"]},
        }})
        td.send({"@type": "setTdlibParameters", "@extra": "setTdlibParameters",
                 "database_directory": str(directory),
                 "database_encryption_key": base64.b64encode(encryption_key).decode(),
                 "use_chat_info_database": True, "api_id": request["api_id"],
                 "api_hash": request["api_hash"], "system_language_code": "en",
                 "device_model": "OpenMediaVault", "application_version": "1"})
        stage = "login"
        wait("setTdlibParameters")
        stage = "proxy"
        wait("offline")
        added = wait("addProxy")
        if not added.get("is_enabled"):
            raise MTProtoError(stage)
        call("setNetworkType", type={"@type": "networkTypeOther"})

        stage = "login"
        while authorization not in ("authorizationStateReady", "authorizationStateWaitPhoneNumber"):
            receive()
        if authorization == "authorizationStateWaitPhoneNumber":
            call("checkAuthenticationBotToken", token=request["bot_token"])
        while authorization != "authorizationStateReady":
            receive()

        stage = "chat"
        target = request["chat_id"]
        if target.startswith("@"):
            chat = call("searchPublicChat", username=target[1:])
        elif int(target) > 0:
            chat = call("createPrivateChat", user_id=int(target), force=False)
            if not chat.get("permissions", {}).get("can_send_basic_messages"):
                # The new bot session can get a private chat before TDLib loads its rights.
                chat = call("getChat", chat_id=chat["id"])
        elif int(target) < -10**12:
            chat = call("createSupergroupChat", supergroup_id=-int(target) - 10**12, force=False)
        else:
            chat = call("createBasicGroupChat", basic_group_id=-int(target), force=False)

        stage = "send"
        message = call("sendMessage", chat_id=chat["id"], input_message_content={
            "@type": "inputMessageText",
            "text": {"@type": "formattedText", "text": request["text"]},
            "link_preview_options": {"@type": "linkPreviewOptions", "is_disabled": True},
        })
        if message.get("sending_state") is not None:
            if message["sending_state"].get("@type") == "messageSendingStateFailed":
                raise MTProtoError(stage)
            while message["id"] not in delivery_updates:
                receive()
            if delivery_updates[message["id"]] != "updateMessageSendSucceeded":
                raise MTProtoError(stage)
    except TimeoutError:
        raise MTProtoError(stage) from None


def main():
    from telegram.tdjson import TDJson

    request = json.load(sys.stdin)
    # Keep each bot's encrypted TDLib database private and serialize access across processes.
    directory = STATE_DIRECTORY / hashlib.sha256(request["bot_token"].encode()).hexdigest()
    directory.mkdir(mode=0o700, exist_ok=True)
    with (directory / "notifier.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        library = importlib.resources.files("telegram").joinpath("lib/libtdjson.so")
        td = TDJson(library_path=str(library), verbosity=0)
        try:
            send(td, request, directory)
        finally:
            td.stop()


if __name__ == "__main__":
    try:
        main()
    except MTProtoError as exc:
        print(exc)
        sys.exit(1)
