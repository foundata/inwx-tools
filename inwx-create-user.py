#!/usr/bin/env python3
"""Create an INWX user account (sub-account for existing INWX accounts)

Credentials are read from environment variables or prompted interactively:
  INWX_API_USER
  INWX_API_PASSWORD
  INWX_API_OTPSECRET

SPDX-FileCopyrightText = "foundata GmbH (https://foundata.com)"
SPDX-License-Identifier = "GPL-3.0-or-later"
"""

from __future__ import annotations

import argparse
import base64
import datetime
import getpass
import hashlib
import hmac
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import string
import struct
import sys
import time
import urllib.error
import urllib.request
import xmlrpc.client
from typing import Any


API_OTE_URL = "https://api.ote.domrobot.com"
API_LIVE_URL = "https://api.domrobot.com"
SUCCESS_CODE = 1000
FULL_ACCESS_ROLE_ID = 20000
VERSION = "1.1.0"  # Semantic Versioning, https://semver.org/
OBJECT_EXISTS_CODE = 2302


class InwxApiError(RuntimeError):
    def __init__(self, method: str, response: dict[str, Any]):
        self.method = method
        self.response = response
        code = response.get("code", "unknown")
        msg = response.get("msg", "no message")
        super().__init__(f"{method} failed with code {code}: {msg}")


class InwxClient:
    def __init__(
        self, api_url: str, language: str = "en", timeout: int = 30, debug: bool = False
    ):
        self.api_url = api_url.rstrip("/")
        self.language = language
        self.timeout = timeout
        self.debug = debug
        cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookie_jar)
        )

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = xmlrpc.client.dumps(
            (params or {},),
            methodname=method,
            encoding="UTF-8",
            allow_none=True,
        )
        request = urllib.request.Request(
            f"{self.api_url}/xmlrpc/",
            data=payload.encode("UTF-8"),
            headers={
                "Content-Type": "text/xml; charset=UTF-8",
                "User-Agent": f"inwx-create-user/{VERSION} (Python {sys.version_info.major}.{sys.version_info.minor})",
            },
            method="POST",
        )
        if self.debug:
            print(
                f">>> {method} {json.dumps(redact(params or {}), sort_keys=True)}",
                file=sys.stderr,
            )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read().decode("UTF-8")
        except urllib.error.HTTPError as err:
            details = err.read().decode("UTF-8", "replace")
            raise RuntimeError(
                f"HTTP {err.code} from INWX API while calling {method}: {details}"
            ) from err
        if self.debug:
            print(f"<<< {method} {body}", file=sys.stderr)
        return xmlrpc.client.loads(body)[0][0]

    def expect_ok(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        response = self.call(method, params)
        if response.get("code") != SUCCESS_CODE:
            raise InwxApiError(method, response)
        return response

    def login(self, username: str, password: str, otp_secret: str | None) -> None:
        response = self.expect_ok(
            "account.login",
            {"lang": self.language, "user": username, "pass": password},
        )
        tfa = str(response.get("resData", {}).get("tfa", "0"))
        if tfa != "0":
            if not otp_secret:
                raise RuntimeError(
                    "INWX requested 2FA, but INWX_API_OTPSECRET is not set."
                )
            self.unlock_with_totp_retry(otp_secret)

    def unlock_with_totp_retry(self, otp_secret: str) -> None:
        last_response: dict[str, Any] | None = None
        for attempt in range(2):
            response = self.call("account.unlock", {"tan": totp(otp_secret)})
            if response.get("code") == SUCCESS_CODE:
                return
            last_response = response
            if attempt == 0:
                time.sleep(31 - (int(time.time()) % 30))
        raise InwxApiError("account.unlock", last_response or {})

    def logout(self) -> None:
        try:
            self.call("account.logout")
        except Exception as exc:  # noqa: BLE001
            print(f"warning: account.logout failed: {exc}", file=sys.stderr)


def totp(shared_secret: str, now: int | None = None) -> str:
    secret = "".join(shared_secret.split()).upper()
    key = base64.b32decode(secret, casefold=True)
    counter = int(now if now is not None else time.time()) // 30
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in {"pass", "password", "currentpassword", "tan"}:
                redacted[key] = "***"
            else:
                redacted[key] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def generated_password(length: int = 40) -> str:
    if length < 10:
        raise ValueError("length must be at least 10")
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def credential(
    name: str, prompt: str, secret: bool = False, optional: bool = False
) -> str | None:
    value = os.environ.get(name)
    if value:
        return value
    if optional:
        value = (
            getpass.getpass(f"{prompt} (leave empty if not used): ")
            if secret
            else input(f"{prompt} (leave empty if not used): ")
        )
        return value or None
    value = getpass.getpass(f"{prompt}: ") if secret else input(f"{prompt}: ")
    if not value:
        raise RuntimeError(f"{name} is required.")
    return value


def first_nonempty(*values: Any) -> Any | None:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def compact_params(params: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in params.items() if value not in (None, "")}


def unique_ints(values: list[int]) -> list[int]:
    result: list[int] = []
    seen: set[int] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def role_ids_from_response(response: dict[str, Any]) -> list[int]:
    roles = response.get("resData", {}).get("roles", [])
    role_ids: list[int] = []
    for role in roles:
        if isinstance(role, dict):
            role_id = role.get("id", role.get("roleId"))
        else:
            role_id = role
        if role_id in (None, ""):
            continue
        role_ids.append(int(role_id))
    return unique_ints(role_ids)


def find_subaccount(client: InwxClient, username: str) -> dict[str, Any] | None:
    accounts = client.expect_ok("account.list").get("resData", {}).get("accounts", [])
    for account in accounts:
        if str(account.get("username", "")).lower() == username.lower():
            return account
    return None


def desired_roles(args: argparse.Namespace) -> list[int]:
    requested_roles = unique_ints(args.role_id)
    keep_full_access = args.keep_full_access or FULL_ACCESS_ROLE_ID in requested_roles
    return unique_ints(
        ([FULL_ACCESS_ROLE_ID] if keep_full_access else [])
        + [role_id for role_id in requested_roles if role_id != FULL_ACCESS_ROLE_ID]
    )


def sync_roles(
    client: InwxClient, account_id: int, target_roles: list[int]
) -> tuple[list[int], list[int], list[int]]:
    current_roles = role_ids_from_response(
        client.expect_ok("account.getroles", {"accountId": account_id})
    )
    to_remove = [role_id for role_id in current_roles if role_id not in target_roles]
    to_add = [role_id for role_id in target_roles if role_id not in current_roles]

    removed_roles: list[int] = []
    added_roles: list[int] = []
    for role_id in to_remove:
        client.expect_ok(
            "account.removerole",
            {"accountId": account_id, "roleId": role_id},
        )
        removed_roles.append(role_id)
    for role_id in to_add:
        client.expect_ok(
            "account.addrole",
            {"accountId": account_id, "roleId": role_id},
        )
        added_roles.append(role_id)
    return target_roles, added_roles, removed_roles


def safe_filename_part(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return safe or "subuser"


def output_file_path(username: str) -> Path:
    timestamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    filename = f"{timestamp}_{safe_filename_part(username)}.txt"
    path = Path(__file__).resolve().parent / filename
    if not path.exists():
        return path
    for index in range(1, 100):
        candidate = path.with_name(f"{path.stem}_{index}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not find an unused output filename for {filename!r}.")


def write_created_user_file(result: dict[str, Any], require_2fa: bool) -> Path:
    path = output_file_path(str(result["username"]))
    lines = [
        "INWX created sub-user",
        f"created_at={datetime.datetime.now().isoformat(timespec='seconds')}",
        f"api_url={result['api_url']}",
        f"accountId={result['accountId']}",
        f"roles={','.join(str(role) for role in result['roles'])}",
        "",
        "# Credentials for the created sub-user",
        f"INWX_API_USER={result['username']}",
    ]
    if "password" in result:
        lines.append(f"INWX_API_PASSWORD={result['password']}")
    else:
        lines.append("INWX_API_PASSWORD=")
        lines.append("# password was not set by this script")
    if require_2fa:
        lines.append("INWX_API_OTPSECRET=")
        lines.append(
            "# required2fa was requested; set the OTP secret after configuring 2FA"
        )
    text = "\n".join(lines) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="UTF-8") as output:
        output.write(text)
    return path


def set_initial_password(
    client: InwxClient,
    username: str,
    password: str,
    retries: int,
    retry_delay: int,
    current_password: str = "",
) -> None:
    params = {
        "username": username,
        "currentpassword": current_password,
        "password": password,
    }
    last_response: dict[str, Any] | None = None
    for attempt in range(retries + 1):
        response = client.call("account.changepassword", params)
        if response.get("code") == SUCCESS_CODE:
            return
        last_response = response
        if response.get("code") == 1200 and attempt < retries:
            print(
                f"password not ready yet; retrying in {retry_delay}s ({attempt + 1}/{retries})",
                file=sys.stderr,
            )
            time.sleep(retry_delay)
            continue
        break
    raise InwxApiError("account.changepassword", last_response or {})


def normalize_title(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    normalized = value.strip().upper()
    aliases = {
        "MR": "MISTER",
        "MR.": "MISTER",
        "MISTER": "MISTER",
        "HERR": "MISTER",
        "MS": "MISS",
        "MS.": "MISS",
        "MRS": "MISS",
        "MRS.": "MISS",
        "MISS": "MISS",
        "FRAU": "MISS",
        "COMPANY": "COMPANY",
        "FIRMA": "COMPANY",
    }
    return aliases.get(normalized, normalized)


def build_create_params(
    args: argparse.Namespace, parent: dict[str, Any]
) -> dict[str, Any]:
    params = {
        "username": args.username,
        "title": normalize_title(first_nonempty(args.title, parent.get("title"))),
        "firstname": first_nonempty(args.firstname, parent.get("firstname")),
        "lastname": first_nonempty(args.lastname, parent.get("lastname")),
        "street": first_nonempty(args.street, parent.get("street")),
        "pc": first_nonempty(args.pc, parent.get("pc")),
        "city": first_nonempty(args.city, parent.get("city")),
        "cc": first_nonempty(args.cc, parent.get("cc")),
        "email": first_nonempty(
            args.email, parent.get("emailAutomated"), parent.get("email")
        ),
        "org": first_nonempty(args.org, parent.get("org")),
        "voice": first_nonempty(args.voice, parent.get("voice")),
        "language": args.language.upper(),
        "required2fa": 1 if args.require_2fa else 0,
    }
    params = compact_params(params)
    missing = [
        field
        for field in (
            "title",
            "firstname",
            "lastname",
            "street",
            "pc",
            "city",
            "cc",
            "email",
        )
        if field not in params
    ]
    if missing:
        missing_list = ", ".join(missing)
        raise RuntimeError(
            f"Missing required account.create field(s): {missing_list}. "
            "Pass them as command line options; parent account.info did not provide usable defaults."
        )
    return params


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an INWX sub-account and optionally grant roles.",
    )
    parser.add_argument("username", help="Username for the INWX sub-account to create.")
    parser.add_argument(
        "--ote",
        action="store_true",
        help="Use the INWX OT&E test API. Default is production.",
    )
    parser.add_argument(
        "--api-url",
        help="Override API base URL, for example https://api.ote.domrobot.com.",
    )
    parser.add_argument(
        "--language", default="EN", help="INWX language code. Default: EN."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print redacted XML-RPC call metadata to stderr.",
    )
    parser.add_argument(
        "--json", action="store_true", help="Print machine-readable result JSON."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "If the username already exists, update that sub-user's roles and "
            "password instead of failing."
        ),
    )
    parser.add_argument(
        "--no-output-file",
        action="store_true",
        help="Do not write the created sub-user credentials file next to this script.",
    )

    parser.add_argument(
        "--password",
        nargs="?",
        const="",
        help="Password for the new sub-account. If used without a value, prompt securely.",
    )
    parser.add_argument(
        "--current-password",
        nargs="?",
        const="",
        help=(
            "Current password for an existing sub-account when using --force. "
            "If used without a value, prompt securely."
        ),
    )
    parser.add_argument(
        "--generate-password",
        action="store_true",
        help="Generate and set a password for the new sub-account.",
    )
    parser.add_argument(
        "--password-retries",
        type=int,
        default=6,
        help="Retries for the initial password change after account.create. Default: 6.",
    )
    parser.add_argument(
        "--password-retry-delay",
        type=int,
        default=10,
        help="Seconds between initial password change retries. Default: 10.",
    )
    parser.add_argument(
        "--require-2fa",
        action="store_true",
        help="Set required2fa=1 for the sub-account.",
    )
    parser.add_argument(
        "--role-id",
        type=int,
        action="append",
        default=[],
        help=(
            "Role id to assign. Repeatable. "
            "20000 (Full Access), 20001 (Accounting), 20002 (Domain), "
            "20003 (Hosting), 20004 (DNS), 20005 (Authcodes)"
        ),
    )
    parser.add_argument(
        "--keep-full-access",
        action="store_true",
        help=(
            "Keep INWX's default Full Access role. By default, Full Access "
            "is removed unless --role-id 20000 is explicitly requested."
        ),
    )

    parser.add_argument("--email", help="Sub-account email. Defaults to parent email.")
    parser.add_argument("--title", help="Sub-account title. Defaults to parent title.")
    parser.add_argument(
        "--firstname", help="Sub-account first name. Defaults to parent first name."
    )
    parser.add_argument(
        "--lastname", help="Sub-account last name. Defaults to parent last name."
    )
    parser.add_argument(
        "--street", help="Sub-account street. Defaults to parent street."
    )
    parser.add_argument(
        "--pc", help="Sub-account postal code. Defaults to parent postal code."
    )
    parser.add_argument("--city", help="Sub-account city. Defaults to parent city.")
    parser.add_argument(
        "--cc", help="Sub-account country code. Defaults to parent country code."
    )
    parser.add_argument(
        "--org", help="Sub-account organization. Defaults to parent organization."
    )
    parser.add_argument(
        "--voice", help="Sub-account phone number. Defaults to parent phone number."
    )

    args = parser.parse_args()
    if args.generate_password and args.password is not None:
        parser.error("--password and --generate-password are mutually exclusive")
    if args.password == "":
        args.password = getpass.getpass("New sub-account password: ")
    elif args.generate_password:
        args.password = generated_password()
    if args.current_password == "":
        args.current_password = getpass.getpass("Current sub-account password: ")
    return args


def main() -> int:
    args = parse_args()
    api_url = args.api_url or (API_OTE_URL if args.ote else API_LIVE_URL)
    client = InwxClient(api_url=api_url, language=args.language, debug=args.debug)

    api_user = credential("INWX_API_USER", "INWX API user")
    api_password = credential("INWX_API_PASSWORD", "INWX API password", secret=True)
    otp_secret = credential(
        "INWX_API_OTPSECRET", "INWX API OTP secret", secret=True, optional=True
    )

    client.login(api_user, api_password, otp_secret)
    try:
        parent_info = client.expect_ok("account.info", {"wide": 1}).get("resData", {})
        create_params = build_create_params(args, parent_info)
        create_response = client.call("account.create", create_params)
        action = "created"
        if create_response.get("code") == SUCCESS_CODE:
            account_id = create_response.get("resData", {}).get("id")
        elif create_response.get("code") == OBJECT_EXISTS_CODE and args.force:
            existing_account = find_subaccount(client, args.username)
            if not existing_account:
                raise RuntimeError(
                    f"account.create says username {args.username!r} already exists, "
                    "but account.list did not return a matching sub-account. "
                    "The account may be deleted/inactive or not manageable by this API user."
                )
            account_id = existing_account.get("id")
            action = "updated"
        else:
            raise InwxApiError("account.create", create_response)
        if not account_id:
            raise RuntimeError(f"Could not determine account id for {args.username!r}.")

        assigned_roles, added_roles, removed_roles = sync_roles(
            client, int(account_id), desired_roles(args)
        )

        if args.password:
            set_initial_password(
                client,
                args.username,
                args.password,
                args.password_retries,
                args.password_retry_delay,
                current_password=args.current_password or "",
            )

        result = {
            "api_url": api_url,
            "action": action,
            "username": args.username,
            "accountId": int(account_id),
            "roles": assigned_roles,
            "addedRoles": added_roles,
            "removedRoles": removed_roles,
        }
        if args.password:
            result["password"] = args.password
        if not args.no_output_file:
            result["outputFile"] = str(
                write_created_user_file(result, args.require_2fa)
            )

        if args.json:
            print(json.dumps(result, sort_keys=True))
        else:
            print(
                f"{action} INWX sub-account {args.username!r} with accountId {account_id}"
            )
            if removed_roles:
                print(
                    f"removed role id(s): {', '.join(str(role) for role in removed_roles)}"
                )
            if added_roles:
                print(
                    f"added role id(s): {', '.join(str(role) for role in added_roles)}"
                )
            else:
                print("added role id(s): none")
            if assigned_roles:
                print(
                    f"assigned role id(s): {', '.join(str(role) for role in assigned_roles)}"
                )
            else:
                print("assigned role id(s): none")
            if args.password:
                print(f"password: {args.password}")
            if "outputFile" in result:
                print(f"saved credentials file: {result['outputFile']}")
        return 0
    finally:
        client.logout()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InwxApiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if exc.response.get("resData"):
            print(
                json.dumps(redact(exc.response["resData"]), sort_keys=True),
                file=sys.stderr,
            )
        raise SystemExit(1)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
