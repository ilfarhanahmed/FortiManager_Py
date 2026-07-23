#!/usr/bin/env python3
"""
FortiManager VPN Manager tunnel-interface IP allocator.

Workflow:
  1. Connect to FortiManager using a REST API administrator token.
  2. List/select an ADOM.
  3. Display managed devices and Device Manager groups.
  4. List/select a VPN Manager community.
  5. Read the community's device/VDOM members.
  6. Discover route-based Phase 1 tunnels matching <community>_<number>
     (or a user-supplied regex).
  7. Correlate both endpoints using reciprocal Phase 1 remote-gw/local gateway.
  8. Allocate one /30 per confirmed pair:
       endpoint A: local IP /32, remote-ip = endpoint B /32
       endpoint B: local IP /32, remote-ip = endpoint A /32
  9. Show a dry-run plan.
 10. With --apply, update only the FortiManager Device Database.

The script never installs configuration to FortiGate devices.

Tested syntax target: FortiManager 7.6.x JSON API.
Python: 3.10+
Dependency: requests

"""

from __future__ import annotations

import argparse
import configparser
import csv
import ipaddress
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence
from urllib.parse import quote

try:
    import requests
    from requests import Session
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Missing dependency: requests. Install it with: py -m pip install requests") from exc


TOOL_VERSION = "final-v8-remote-ip-32"
DEFAULT_CONFIG_FILES = ("config.ini", "fmg_vpn_tunnel_ip.ini")
UNSET_CIDRS = {"", "0.0.0.0/0", "0.0.0.0 0.0.0.0", "0.0.0.0/255.255.255.255"}
SUPPORTED_ADOM_OS_TYPES = {"fos", "foc", "ffw", "fwc", "fpx"}


class ToolError(RuntimeError):
    """Expected, user-facing tool error."""


class FmgApiError(ToolError):
    """FortiManager JSON API error."""

    def __init__(self, message: str, *, code: int | None = None, response: Any = None):
        super().__init__(message)
        self.code = code
        self.response = response


@dataclass(frozen=True, order=True)
class EndpointKey:
    device: str
    vdom: str
    phase1: str

    def text(self) -> str:
        return f"{self.device}/{self.vdom}/{self.phase1}"


@dataclass
class Member:
    device: str
    vdom: str
    role: str = ""
    node_id: str = ""


@dataclass
class Endpoint:
    key: EndpointKey
    outgoing_interface: str
    phase1_type: str
    remote_gw: str | None
    local_gateways: list[str]
    phase1_raw: dict[str, Any]
    interface_raw: dict[str, Any]

    @property
    def local_ip_raw(self) -> Any:
        return self.interface_raw.get("ip")

    @property
    def remote_ip_raw(self) -> Any:
        return self.interface_raw.get("remote-ip")


@dataclass
class TunnelPair:
    a: Endpoint
    b: Endpoint
    status: str = ""
    reason: str = ""
    existing_subnet: str | None = None

    def pair_id(self) -> str:
        keys = sorted((self.a.key, self.b.key))
        return f"{keys[0].text()} <-> {keys[1].text()}"


@dataclass
class Allocation:
    pair_id: str
    subnet: str
    a_device: str
    a_vdom: str
    a_tunnel: str
    a_local_ip: str
    a_remote_ip: str
    b_device: str
    b_vdom: str
    b_tunnel: str
    b_local_ip: str
    b_remote_ip: str
    a_old_ip: Any = None
    a_old_remote_ip: Any = None
    b_old_ip: Any = None
    b_old_remote_ip: Any = None

    def changes(self) -> list[dict[str, Any]]:
        return [
            {
                "device": self.a_device,
                "vdom": self.a_vdom,
                "interface": self.a_tunnel,
                "old_ip": self.a_old_ip,
                "old_remote_ip": self.a_old_remote_ip,
                "new_ip": self.a_local_ip,
                "new_remote_ip": self.a_remote_ip,
                "pair_id": self.pair_id,
                "subnet": self.subnet,
            },
            {
                "device": self.b_device,
                "vdom": self.b_vdom,
                "interface": self.b_tunnel,
                "old_ip": self.b_old_ip,
                "old_remote_ip": self.b_old_remote_ip,
                "new_ip": self.b_local_ip,
                "new_remote_ip": self.b_remote_ip,
                "pair_id": self.pair_id,
                "subnet": self.subnet,
            },
        ]


@dataclass
class DiscoveryResult:
    community: dict[str, Any]
    members: list[Member]
    endpoints: list[Endpoint]
    pairs: list[TunnelPair]
    unresolved: list[dict[str, str]]
    interface_cache: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


class FmgClient:
    def __init__(
        self,
        host: str,
        api_key: str,
        *,
        verify_ssl: bool = True,
        timeout: int = 30,
        debug: bool = False,
    ) -> None:
        host = host.strip().rstrip("/")
        if not host.startswith(("https://", "http://")):
            host = f"https://{host}"
        self.host = host
        self.url = f"{host}/jsonrpc"
        self.timeout = timeout
        self.debug = debug
        self._request_id = 1
        self.session: Session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
                requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore[attr-defined]
            )

    def call(self, method: str, params: list[dict[str, Any]]) -> list[dict[str, Any]]:
        payload = {
            "id": self._request_id,
            "method": method,
            "params": params,
        }
        self._request_id += 1
        if self.debug:
            redacted = json.loads(json.dumps(payload))
            print(f"\n[DEBUG] Request:\n{json.dumps(redacted, indent=2, default=str)}", file=sys.stderr)
        try:
            response = self.session.post(self.url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            body = response.json()
        except requests.RequestException as exc:
            raise FmgApiError(f"Unable to communicate with FortiManager: {exc}") from exc
        except ValueError as exc:
            raise FmgApiError("FortiManager returned a non-JSON response.") from exc

        if self.debug:
            print(f"[DEBUG] Response:\n{json.dumps(body, indent=2, default=str)}", file=sys.stderr)

        results = body.get("result")
        if not isinstance(results, list):
            raise FmgApiError("Unexpected FortiManager response: missing result array.", response=body)
        return results

    @staticmethod
    def _status(result: dict[str, Any]) -> tuple[int, str]:
        status = result.get("status") or {}
        code = int(status.get("code", -99999))
        message = str(status.get("message", "Unknown error"))
        return code, message

    def call_one(
        self,
        method: str,
        url: str,
        *,
        data: Any = None,
        option: str | None = None,
        fields: Sequence[str] | None = None,
        verbose: int | None = None,
        allow_error: bool = False,
    ) -> dict[str, Any]:
        param: dict[str, Any] = {"url": url}
        if data is not None:
            param["data"] = data
        if option:
            param["option"] = option
        if fields:
            param["fields"] = list(fields)
        if verbose is not None:
            param["verbose"] = verbose
        result = self.call(method, [param])[0]
        code, message = self._status(result)
        if code != 0 and not allow_error:
            raise FmgApiError(f"FMG API error {code} for {method} {url}: {message}", code=code, response=result)
        return result

    def get(
        self,
        url: str,
        *,
        option: str | None = None,
        fields: Sequence[str] | None = None,
        verbose: int | None = None,
    ) -> Any:
        return self.call_one(
            "get", url, option=option, fields=fields, verbose=verbose
        ).get("data")

    def update_batch(self, params: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results = self.call("update", params)
        failures: list[str] = []
        for index, result in enumerate(results):
            code, message = self._status(result)
            if code != 0:
                url = params[index].get("url", "?") if index < len(params) else "?"
                failures.append(f"{url}: [{code}] {message}")
        if failures:
            raise FmgApiError("One or more FMG updates failed:\n  " + "\n  ".join(failures), response=results)
        return results

    def exec(self, url: str, *, data: Any = None, allow_error: bool = False) -> dict[str, Any]:
        return self.call_one("exec", url, data=data, allow_error=allow_error)


def path_component(value: str) -> str:
    return quote(value, safe="")


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def table_rows(data: Any) -> list[dict[str, Any]]:
    if data is None:
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        # Some endpoints wrap table rows in a named key.
        for value in data.values():
            if isinstance(value, list) and all(isinstance(x, dict) for x in value):
                return value
        return [data]
    return []


def ref_name(value: Any) -> str:
    """Normalize FMG datasource/reference values to one string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        for item in value:
            name = ref_name(item)
            if name:
                return name
        return ""
    if isinstance(value, dict):
        for key in ("name", "value", "device", "dev", "member"):
            if key in value:
                name = ref_name(value[key])
                if name:
                    return name
    return ""


def get_any(mapping: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return default


def ipv4_text(value: Any) -> str | None:
    if value is None:
        return None
    candidates: list[str] = []
    if isinstance(value, str):
        candidates.extend(re.split(r"[\s,/]+", value.strip()))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                candidates.extend(re.split(r"[\s,/]+", item.strip()))
    elif isinstance(value, dict):
        for key in ("ip", "address", "value"):
            if key in value:
                return ipv4_text(value[key])
    for candidate in candidates:
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv4Address) and not ip.is_unspecified:
            return str(ip)
    return None


def mask_to_prefix(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def normalize_cidr(value: Any) -> str | None:
    """Normalize FMG IPv4 address/mask representations to CIDR text."""
    if value is None:
        return None
    if isinstance(value, dict):
        for key in ("value", "ip", "address"):
            if key in value:
                return normalize_cidr(value[key])
        return None
    if isinstance(value, list):
        if len(value) >= 2 and all(isinstance(x, str) for x in value[:2]):
            return normalize_cidr(f"{value[0]} {value[1]}")
        if len(value) == 1:
            return normalize_cidr(value[0])
        return None
    text = str(value).strip()
    if text.lower() in {"none", "null", "unset"} or text in UNSET_CIDRS:
        return None
    if not text:
        return None

    # CIDR syntax.
    if "/" in text:
        ip_part, mask_part = text.split("/", 1)
        ip_part = ip_part.strip()
        mask_part = mask_part.strip()
        try:
            prefix = int(mask_part) if mask_part.isdigit() else mask_to_prefix(mask_part)
            return str(ipaddress.IPv4Interface(f"{ip_part}/{prefix}"))
        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return None

    # "IP NETMASK" syntax.
    parts = text.split()
    if len(parts) >= 2:
        try:
            return str(ipaddress.IPv4Interface(f"{parts[0]}/{mask_to_prefix(parts[1])}"))
        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return None

    # Bare address: treat as /32.
    try:
        return str(ipaddress.IPv4Interface(f"{text}/32"))
    except ValueError:
        return None


def cidr_interface(value: Any) -> ipaddress.IPv4Interface | None:
    normalized = normalize_cidr(value)
    if not normalized:
        return None
    try:
        return ipaddress.IPv4Interface(normalized)
    except ValueError:
        return None


def is_unset(value: Any) -> bool:
    return normalize_cidr(value) is None


def normalize_for_compare(value: Any) -> str | None:
    return normalize_cidr(value)


def load_json_file(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError(f"Unable to read JSON file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ToolError(f"JSON file {path} must contain an object at its top level.")
    return data


def choose_item(title: str, rows: Sequence[dict[str, Any]], label_func, preselected: str | None = None) -> dict[str, Any]:
    if not rows:
        raise ToolError(f"No {title.lower()} found.")
    if preselected:
        for row in rows:
            if str(row.get("name", "")) == preselected:
                return row
        raise ToolError(f"{title} '{preselected}' was not found.")

    print(f"\n{title}:")
    for index, row in enumerate(rows, start=1):
        print(f"  {index:>3}. {label_func(row)}")
    while True:
        answer = input(f"Select {title.lower()} [1-{len(rows)}]: ").strip()
        try:
            selected = int(answer)
        except ValueError:
            print("Enter a number from the list.")
            continue
        if 1 <= selected <= len(rows):
            return rows[selected - 1]
        print("Selection is out of range.")


def adom_product_code(row: dict[str, Any]) -> str:
    """Return the ADOM restricted product code in normalized text form.

    FortiManager calls this field ``restricted_prds``.  With ``verbose=1`` it
    is normally returned as text, for example ``fos`` or ``fpx``.  Numeric
    fallback values are supported for FMG builds that still return the enum.
    """
    value = get_any(
        row,
        "restricted_prds",
        "restricted-prds",
        "restricted prds",
        default="",
    )

    if isinstance(value, list):
        value = value[0] if value else ""

    if isinstance(value, dict):
        value = get_any(value, "name", "value", "id", default="")

    text_value = str(value).strip().lower()
    if not text_value:
        return ""

    # Enum order from the FortiManager JSON API reference.  This is only a
    # fallback; verbose output should normally provide the text value directly.
    numeric_product_codes = {
        0: "sim", 1: "fos", 2: "foc", 3: "fml", 4: "fch",
        5: "fwb", 6: "log", 7: "fct", 8: "faz", 9: "fsa",
        10: "fsw", 11: "fmg", 12: "fdd", 13: "fac", 14: "fpx",
        15: "fna", 16: "ffw", 17: "fsr", 18: "fad", 19: "fdc",
        20: "fap", 21: "fxt", 22: "fts", 23: "fai", 24: "fwc",
        25: "fis", 26: "fed", 27: "fpa", 28: "fca", 29: "ftc",
        30: "fss", 31: "fra", 32: "fabric",
    }
    if text_value.isdigit():
        return numeric_product_codes.get(int(text_value), text_value)

    return text_value


def get_adoms(client: FmgClient) -> list[dict[str, Any]]:
    # verbose=1 is required so restricted_prds is returned as a product code
    # such as fos/foc/ffw/fwc/fpx rather than an enum number.
    rows = table_rows(client.get("/dvmdb/adom", verbose=1))
    usable: list[dict[str, Any]] = []

    for row in rows:
        name = str(row.get("name", "")).strip()
        if not name or name == "rootp":
            continue

        product = adom_product_code(row)
        if product not in SUPPORTED_ADOM_OS_TYPES:
            continue

        usable.append(row)

    if not usable:
        raise ToolError(
            "No FortiGate-compatible ADOMs were returned. Expected "
            "restricted_prds to be one of: "
            + ", ".join(sorted(SUPPORTED_ADOM_OS_TYPES))
            + ". Run with --debug to inspect the /dvmdb/adom response."
        )

    return sorted(usable, key=lambda x: str(x.get("name", "")).lower())


def get_devices(client: FmgClient, adom: str) -> list[dict[str, Any]]:
    url = f"/dvmdb/adom/{path_component(adom)}/device"
    return sorted(table_rows(client.get(url)), key=lambda x: str(x.get("name", "")).lower())


def get_groups(client: FmgClient, adom: str) -> list[dict[str, Any]]:
    url = f"/dvmdb/adom/{path_component(adom)}/group"
    return sorted(table_rows(client.get(url)), key=lambda x: str(x.get("name", "")).lower())


def get_communities(client: FmgClient, adom: str) -> list[dict[str, Any]]:
    url = f"/pm/config/adom/{path_component(adom)}/obj/vpnmgr/vpntable"
    return sorted(table_rows(client.get(url)), key=lambda x: str(x.get("name", "")).lower())


def get_vpn_nodes(client: FmgClient, adom: str) -> list[dict[str, Any]]:
    url = f"/pm/config/adom/{path_component(adom)}/obj/vpnmgr/node"
    return table_rows(client.get(url, option="scope member"))


def extract_scope_members(node: dict[str, Any]) -> list[dict[str, Any]]:
    scope = get_any(node, "scope member", "scope-member", "scope_member", "scope")
    if scope is None:
        return []
    if isinstance(scope, dict):
        # Some responses wrap members under a nested key.
        for key in ("member", "members", "scope member", "scope-member"):
            if key in scope:
                return [x for x in as_list(scope[key]) if isinstance(x, dict)]
        return [scope]
    return [x for x in as_list(scope) if isinstance(x, dict)]


def community_members(
    nodes: list[dict[str, Any]],
    community_name: str,
    devices_by_name: dict[str, dict[str, Any]],
    groups_by_name: dict[str, dict[str, Any]],
) -> tuple[list[Member], list[str]]:
    members: dict[tuple[str, str], Member] = {}
    warnings: list[str] = []

    for node in nodes:
        if ref_name(node.get("vpntable")) != community_name:
            continue
        scopes = extract_scope_members(node)
        if not scopes:
            warnings.append(f"VPN node {node.get('id', '?')} has no returned scope member.")
            continue
        for scope in scopes:
            name = ref_name(get_any(scope, "name", "device", "dev", "member"))
            vdom = ref_name(get_any(scope, "vdom", "vdom-name", "vdom_name")) or "root"
            if not name:
                warnings.append(f"VPN node {node.get('id', '?')} has an unreadable scope member: {scope!r}")
                continue
            if name in groups_by_name and name not in devices_by_name:
                warnings.append(
                    f"VPN node {node.get('id', '?')} uses Device Manager group '{name}'. "
                    "Automatic group expansion is not performed; assign devices directly or supply a community with direct members."
                )
                continue
            if name not in devices_by_name:
                warnings.append(f"VPN node {node.get('id', '?')} references unknown device '{name}'.")
                continue
            key = (name, vdom)
            members[key] = Member(
                device=name,
                vdom=vdom,
                role=str(node.get("role", "")),
                node_id=str(node.get("id", "")),
            )

    return sorted(members.values(), key=lambda x: (x.device.lower(), x.vdom.lower())), warnings


def get_phase1_interfaces(client: FmgClient, device: str, vdom: str) -> list[dict[str, Any]]:
    url = (
        f"/pm/config/device/{path_component(device)}/vdom/{path_component(vdom)}"
        "/vpn/ipsec/phase1-interface"
    )
    # Send JSON-RPC parameter: "verbose": 1.
    # This returns FortiManager enum fields in their text representation.
    return table_rows(client.get(url, verbose=1))


def get_system_interfaces(client: FmgClient, device: str) -> list[dict[str, Any]]:
    url = f"/pm/config/device/{path_component(device)}/global/system/interface"

    # IMPORTANT: this produces the following FortiManager JSON-RPC parameter:
    #     {"url": "/pm/config/device/<device>/global/system/interface",
    #      "verbose": 1}
    # Without verbose=1, FortiManager may return interface type as numeric enum 4.
    # With verbose=1, the same field is returned as the text value "tunnel".
    return table_rows(client.get(url, verbose=1))


def interface_vdom(interface: dict[str, Any]) -> str:
    return ref_name(interface.get("vdom")) or "root"


def is_tunnel_interface(interface: dict[str, Any]) -> bool:
    """Accept verbose text output and numeric FMG enum output as fallback."""
    value = interface.get("type")
    if value in (None, ""):
        return True
    if isinstance(value, str):
        return value.strip().lower() == "tunnel" or value.strip() == "4"
    return value == 4


def find_interface(
    interfaces: Sequence[dict[str, Any]],
    name: str,
    vdom: str,
) -> dict[str, Any] | None:
    exact = [x for x in interfaces if str(x.get("name", "")) == name and interface_vdom(x) == vdom]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        return None
    # Some single-VDOM API responses omit the vdom field.
    name_matches = [x for x in interfaces if str(x.get("name", "")) == name]
    return name_matches[0] if len(name_matches) == 1 else None


def gateway_override(
    overrides: dict[str, Any],
    device: str,
    vdom: str,
    phase1: str,
    outgoing_interface: str,
) -> str | None:
    keys = (
        f"{device}|{vdom}|{phase1}",
        f"{device}|{vdom}|{outgoing_interface}",
        f"{device}|{vdom}",
        device,
    )
    for key in keys:
        if key in overrides:
            return ipv4_text(overrides[key])
    return None


def discover_endpoints(
    client: FmgClient,
    members: list[Member],
    tunnel_pattern: re.Pattern[str],
    gateway_overrides: dict[str, Any],
) -> tuple[list[Endpoint], list[dict[str, str]], dict[str, list[dict[str, Any]]]]:
    endpoints: list[Endpoint] = []
    unresolved: list[dict[str, str]] = []
    interface_cache: dict[str, list[dict[str, Any]]] = {}

    for member in members:
        if member.device not in interface_cache:
            interface_cache[member.device] = get_system_interfaces(client, member.device)
        interfaces = interface_cache[member.device]
        phase1s = get_phase1_interfaces(client, member.device, member.vdom)

        for phase1 in phase1s:
            phase1_name = str(phase1.get("name", ""))
            if not tunnel_pattern.fullmatch(phase1_name):
                continue

            key = EndpointKey(member.device, member.vdom, phase1_name)
            p1_type = str(phase1.get("type", "static") or "static").lower()
            remote_gw = ipv4_text(phase1.get("remote-gw"))
            outgoing = ref_name(phase1.get("interface"))
            tunnel_interface = find_interface(interfaces, phase1_name, member.vdom)

            if p1_type != "static":
                unresolved.append({"endpoint": key.text(), "reason": f"Phase 1 type is '{p1_type}', not static."})
                continue
            if not remote_gw:
                ddns = str(phase1.get("remotegw-ddns", ""))
                reason = "No static IPv4 remote-gw is configured."
                if ddns:
                    reason += f" DDNS peer: {ddns}."
                unresolved.append({"endpoint": key.text(), "reason": reason})
                continue
            if not tunnel_interface:
                unresolved.append(
                    {"endpoint": key.text(), "reason": "Matching system/interface tunnel object was not found."}
                )
                continue
            if not is_tunnel_interface(tunnel_interface):
                unresolved.append(
                    {
                        "endpoint": key.text(),
                        "reason": f"Matching system/interface object type is '{tunnel_interface.get('type')}', not tunnel.",
                    }
                )
                continue

            gateways: list[str] = []
            override = gateway_override(
                gateway_overrides,
                member.device,
                member.vdom,
                phase1_name,
                outgoing,
            )
            if override:
                gateways.append(override)
            local_gw = ipv4_text(phase1.get("local-gw"))
            if local_gw and local_gw not in gateways:
                gateways.append(local_gw)
            if outgoing:
                outgoing_obj = find_interface(interfaces, outgoing, member.vdom)
                if outgoing_obj:
                    outgoing_ip = cidr_interface(outgoing_obj.get("ip"))
                    if outgoing_ip and not outgoing_ip.ip.is_unspecified:
                        value = str(outgoing_ip.ip)
                        if value not in gateways:
                            gateways.append(value)

            if not gateways:
                unresolved.append(
                    {
                        "endpoint": key.text(),
                        "reason": (
                            f"Local external gateway could not be determined from local-gw or outgoing interface '{outgoing}'. "
                            "Use --gateway-map for DHCP, PPPoE, or NAT cases."
                        ),
                    }
                )
                continue

            endpoints.append(
                Endpoint(
                    key=key,
                    outgoing_interface=outgoing,
                    phase1_type=p1_type,
                    remote_gw=remote_gw,
                    local_gateways=gateways,
                    phase1_raw=phase1,
                    interface_raw=tunnel_interface,
                )
            )

    return sorted(endpoints, key=lambda x: x.key), unresolved, interface_cache


def reciprocal_match(a: Endpoint, b: Endpoint) -> bool:
    if a.key.device == b.key.device:
        return False
    if not a.remote_gw or not b.remote_gw:
        return False
    return a.remote_gw in b.local_gateways and b.remote_gw in a.local_gateways


def pair_endpoints(endpoints: list[Endpoint]) -> tuple[list[TunnelPair], list[dict[str, str]]]:
    candidates: dict[EndpointKey, list[Endpoint]] = {endpoint.key: [] for endpoint in endpoints}
    for index, a in enumerate(endpoints):
        for b in endpoints[index + 1 :]:
            if reciprocal_match(a, b):
                candidates[a.key].append(b)
                candidates[b.key].append(a)

    pairs: list[TunnelPair] = []
    unresolved: list[dict[str, str]] = []
    processed: set[EndpointKey] = set()

    by_key = {endpoint.key: endpoint for endpoint in endpoints}
    for endpoint in endpoints:
        if endpoint.key in processed:
            continue
        matches = candidates[endpoint.key]
        if len(matches) == 1:
            peer = matches[0]
            peer_matches = candidates[peer.key]
            if len(peer_matches) == 1 and peer_matches[0].key == endpoint.key:
                pairs.append(TunnelPair(endpoint, peer))
                processed.add(endpoint.key)
                processed.add(peer.key)
                continue
        if not matches:
            reason = (
                f"No reciprocal endpoint found for remote-gw {endpoint.remote_gw}; "
                f"local gateway candidates were {', '.join(endpoint.local_gateways)}."
            )
        else:
            reason = "Multiple reciprocal endpoints matched: " + ", ".join(x.key.text() for x in matches)
        unresolved.append({"endpoint": endpoint.key.text(), "reason": reason})
        processed.add(endpoint.key)

    # Defensive check for endpoints referenced but not processed.
    for key in by_key:
        if key not in processed:
            unresolved.append({"endpoint": key.text(), "reason": "Endpoint was not paired."})

    pairs.sort(key=lambda p: p.pair_id().lower())
    return pairs, unresolved


def validate_existing_pair(pair: TunnelPair) -> None:
    a_local = cidr_interface(pair.a.local_ip_raw)
    b_local = cidr_interface(pair.b.local_ip_raw)
    a_remote = cidr_interface(pair.a.remote_ip_raw)
    b_remote = cidr_interface(pair.b.remote_ip_raw)

    values = (a_local, b_local, a_remote, b_remote)
    if all(value is None for value in values):
        pair.status = "eligible"
        return
    if any(value is None for value in values):
        pair.status = "partial"
        pair.reason = "Only part of the local IP/remote-ip configuration exists."
        return

    assert a_local and b_local and a_remote and b_remote

    # Both the local tunnel IP and peer remote-ip are host addresses (/32).
    # The /30 is only the allocation block used to reserve two adjacent host
    # addresses for the point-to-point tunnel pair.
    a_block = ipaddress.ip_network(f"{a_local.ip}/30", strict=False)
    b_block = ipaddress.ip_network(f"{b_local.ip}/30", strict=False)
    usable_hosts = set(a_block.hosts())

    valid = (
        a_local.network.prefixlen == 32
        and b_local.network.prefixlen == 32
        and a_remote.network.prefixlen == 32
        and b_remote.network.prefixlen == 32
        and a_remote.ip == b_local.ip
        and b_remote.ip == a_local.ip
        and a_block == b_block
        and a_local.ip in usable_hosts
        and b_local.ip in usable_hosts
        and a_local.ip != b_local.ip
    )
    if valid:
        pair.status = "configured"
        pair.existing_subnet = str(a_block)
    else:
        pair.status = "conflict"
        pair.reason = (
            "Existing local IP and remote-ip values are not reciprocal /32 host "
            "addresses from the same /30 allocation block."
        )


def validate_pairs(pairs: list[TunnelPair]) -> None:
    for pair in pairs:
        validate_existing_pair(pair)


def collect_used_networks(interface_cache: dict[str, list[dict[str, Any]]]) -> list[ipaddress.IPv4Network]:
    networks: set[ipaddress.IPv4Network] = set()
    for interfaces in interface_cache.values():
        for interface in interfaces:
            for field_name in ("ip", "remote-ip"):
                parsed = cidr_interface(interface.get(field_name))
                if not parsed or parsed.ip.is_unspecified:
                    continue
                networks.add(parsed.network)
    return sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))


def parse_pool(pool_text: str) -> ipaddress.IPv4Network:
    value = pool_text.strip()
    if not value:
        raise ToolError("The IPv4 tunnel pool cannot be blank.")
    try:
        pool = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ToolError(f"Invalid IPv4 pool '{pool_text}': {exc}") from exc
    if not isinstance(pool, ipaddress.IPv4Network):
        raise ToolError("Only IPv4 pools are supported.")
    if pool.prefixlen > 30:
        raise ToolError("The pool must be /30 or larger (for example /24, /20, or /16).")
    return pool


def get_pool_from_user(provided_pool: str | None) -> ipaddress.IPv4Network:
    """Validate --pool or repeatedly prompt until a valid IPv4 CIDR is entered."""
    if provided_pool is not None:
        return parse_pool(provided_pool)

    while True:
        try:
            value = input(
                "\nEnter IPv4 tunnel pool (for example 10.240.0.0/24): "
            ).strip()
        except EOFError as exc:
            raise ToolError(
                "No IPv4 tunnel pool was entered. Use --pool <IPv4-CIDR> when running non-interactively."
            ) from exc
        except KeyboardInterrupt as exc:
            raise ToolError("Operation cancelled while waiting for the IPv4 tunnel pool.") from exc

        if not value:
            print("[WARN] The IPv4 tunnel pool cannot be blank. Enter a CIDR such as 10.240.0.0/24.")
            continue

        try:
            return parse_pool(value)
        except ToolError as exc:
            print(f"[WARN] {exc}")


def subnet_overlaps_used(subnet: ipaddress.IPv4Network, used: Sequence[ipaddress.IPv4Network]) -> bool:
    return any(subnet.overlaps(network) for network in used)


def available_subnets(
    pool: ipaddress.IPv4Network,
    used_networks: Sequence[ipaddress.IPv4Network],
    required: int,
) -> tuple[list[ipaddress.IPv4Network], int]:
    theoretical = 1 << (30 - pool.prefixlen)
    if theoretical < required:
        raise ToolError(
            f"Pool {pool} contains only {theoretical} /30 networks, but {required} are required."
        )

    selected: list[ipaddress.IPv4Network] = []
    skipped = 0
    for subnet in pool.subnets(new_prefix=30):
        if subnet_overlaps_used(subnet, used_networks):
            skipped += 1
            continue
        selected.append(subnet)
        if len(selected) == required:
            break
    if len(selected) < required:
        raise ToolError(
            f"Pool {pool} does not contain {required} non-overlapping /30 networks. "
            f"Only {len(selected)} were available after excluding discovered interface networks."
        )
    return selected, skipped


def allocate_pairs(pairs: list[TunnelPair], subnets: list[ipaddress.IPv4Network]) -> list[Allocation]:
    allocations: list[Allocation] = []
    for pair, subnet in zip(sorted(pairs, key=lambda p: p.pair_id().lower()), subnets, strict=True):
        endpoints = sorted((pair.a, pair.b), key=lambda endpoint: endpoint.key)
        a, b = endpoints
        hosts = list(subnet.hosts())
        if len(hosts) != 2:
            raise ToolError(f"Unexpected /30 subnet host count for {subnet}.")
        a_ip, b_ip = hosts
        allocations.append(
            Allocation(
                pair_id=f"{a.key.text()} <-> {b.key.text()}",
                subnet=str(subnet),
                a_device=a.key.device,
                a_vdom=a.key.vdom,
                a_tunnel=a.key.phase1,
                a_local_ip=f"{a_ip}/32",
                a_remote_ip=f"{b_ip}/32",
                b_device=b.key.device,
                b_vdom=b.key.vdom,
                b_tunnel=b.key.phase1,
                b_local_ip=f"{b_ip}/32",
                b_remote_ip=f"{a_ip}/32",
                a_old_ip=a.local_ip_raw,
                a_old_remote_ip=a.remote_ip_raw,
                b_old_ip=b.local_ip_raw,
                b_old_remote_ip=b.remote_ip_raw,
            )
        )
    return allocations


def print_devices_and_groups(devices: list[dict[str, Any]], groups: list[dict[str, Any]]) -> None:
    print(f"\nManaged devices: {len(devices)}")
    for device in devices:
        name = str(device.get("name", "?"))
        serial = str(device.get("sn", ""))
        status = str(get_any(device, "conf_status", "conf-status", default=""))
        print(f"  - {name:<36} {serial:<18} {status}")

    print(f"\nDevice Manager groups: {len(groups)}")
    for group in groups:
        name = str(group.get("name", "?"))
        description = str(group.get("desc", ""))
        print(f"  - {name:<36} {description}")


def print_members(members: list[Member]) -> None:
    print(f"\nCommunity members: {len(members)}")
    for member in members:
        role = f" ({member.role})" if member.role else ""
        print(f"  - {member.device}/{member.vdom}{role}")


def print_unresolved(unresolved: list[dict[str, str]]) -> None:
    if not unresolved:
        return
    print(f"\nUnresolved endpoints: {len(unresolved)}")
    for item in unresolved:
        print(f"  - {item.get('endpoint', '?')}: {item.get('reason', '')}")


def print_pair_summary(pairs: list[TunnelPair]) -> None:
    counts: dict[str, int] = {}
    for pair in pairs:
        counts[pair.status] = counts.get(pair.status, 0) + 1
    print(f"\nMatched tunnel pairs: {len(pairs)}")
    for status in ("eligible", "configured", "partial", "conflict"):
        if counts.get(status):
            print(f"  {status:<12}: {counts[status]}")
    for pair in pairs:
        if pair.status in {"partial", "conflict"}:
            print(f"  - {pair.pair_id()}: {pair.status.upper()} — {pair.reason}")


def print_plan(allocations: list[Allocation]) -> None:
    print(f"\nPlanned interface updates: {len(allocations) * 2}")
    headers = ("Device", "VDOM", "Tunnel", "Local IP", "Remote IP", "Subnet")
    rows: list[tuple[str, ...]] = []
    for allocation in allocations:
        rows.extend(
            [
                (
                    allocation.a_device,
                    allocation.a_vdom,
                    allocation.a_tunnel,
                    allocation.a_local_ip,
                    allocation.a_remote_ip,
                    allocation.subnet,
                ),
                (
                    allocation.b_device,
                    allocation.b_vdom,
                    allocation.b_tunnel,
                    allocation.b_local_ip,
                    allocation.b_remote_ip,
                    allocation.subnet,
                ),
            ]
        )
    widths = [len(value) for value in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    fmt = "  " + "  ".join(f"{{:<{width}}}" for width in widths)
    print(fmt.format(*headers))
    print(fmt.format(*("-" * width for width in widths)))
    for row in rows:
        print(fmt.format(*row))


def create_output_dir(base: str | None, community: str) -> Path:
    if base:
        path = Path(base)
    else:
        safe_community = re.sub(r"[^A-Za-z0-9_.-]+", "_", community)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(f"fmg_vpn_tunnel_ip_{safe_community}_{stamp}")
    path.mkdir(parents=True, exist_ok=True)
    return path


def export_results(
    output_dir: Path,
    *,
    host: str,
    adom: str,
    community: str,
    tunnel_regex: str,
    pool: str | None,
    allocations: list[Allocation],
    unresolved: list[dict[str, str]],
    pairs: list[TunnelPair],
) -> None:
    plan = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "fortimanager": host,
        "adom": adom,
        "community": community,
        "tunnel_regex": tunnel_regex,
        "pool": pool,
        "allocations": [asdict(item) for item in allocations],
        "pair_status": [
            {
                "pair_id": pair.pair_id(),
                "status": pair.status,
                "reason": pair.reason,
                "existing_subnet": pair.existing_subnet,
            }
            for pair in pairs
        ],
        "unresolved": unresolved,
    }
    (output_dir / "plan.json").write_text(json.dumps(plan, indent=2, default=str), encoding="utf-8")

    with (output_dir / "plan.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "pair_id",
                "subnet",
                "device",
                "vdom",
                "interface",
                "local_ip",
                "remote_ip",
            ],
        )
        writer.writeheader()
        for allocation in allocations:
            writer.writerow(
                {
                    "pair_id": allocation.pair_id,
                    "subnet": allocation.subnet,
                    "device": allocation.a_device,
                    "vdom": allocation.a_vdom,
                    "interface": allocation.a_tunnel,
                    "local_ip": allocation.a_local_ip,
                    "remote_ip": allocation.a_remote_ip,
                }
            )
            writer.writerow(
                {
                    "pair_id": allocation.pair_id,
                    "subnet": allocation.subnet,
                    "device": allocation.b_device,
                    "vdom": allocation.b_vdom,
                    "interface": allocation.b_tunnel,
                    "local_ip": allocation.b_local_ip,
                    "remote_ip": allocation.b_remote_ip,
                }
            )

    with (output_dir / "unresolved.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["endpoint", "reason"])
        writer.writeheader()
        writer.writerows(unresolved)


def interface_object_url(device: str, interface: str) -> str:
    return (
        f"/pm/config/device/{path_component(device)}/global/system/interface/"
        f"{path_component(interface)}"
    )


def change_records(allocations: list[Allocation]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for allocation in allocations:
        records.extend(allocation.changes())
    return records


def write_rollback(output_dir: Path, host: str, adom: str, changes: list[dict[str, Any]]) -> Path:
    """Write the authoritative API rollback file.

    A combined FortiGate CLI rollback file is intentionally not generated. A
    single CLI file containing commands for multiple devices can be executed on
    the wrong FortiGate and create unintended interface objects.
    """
    rollback = {
        "format_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "fortimanager": host,
        "adom": adom,
        "changes": changes,
    }
    path = output_dir / "rollback.json"
    path.write_text(json.dumps(rollback, indent=2, default=str), encoding="utf-8")

    instructions = f"""FMG VPN TUNNEL IP ROLLBACK
================================

The supported rollback method is the FortiManager JSON API rollback.

Run:

    py fmg_vpn_tunnel_ip_final_v8.py --rollback \"{path}\"

The rollback operation:

1. Connects to FortiManager.
2. Retrieves every recorded interface from the correct managed device.
3. Confirms the expected VDOM and tunnel-interface type.
4. Confirms the interface still contains the values written by this plan.
5. Restores the previous ip and remote-ip values.
6. Reads the interfaces again and verifies the restored values.

The rollback changes only the FortiManager Device Database. It does not install
configuration to FortiGate devices. If the original changes were installed,
install the restored Device Database configuration from FortiManager afterward.
"""
    (output_dir / "ROLLBACK_INSTRUCTIONS.txt").write_text(
        instructions,
        encoding="utf-8",
    )
    return path

def values_match(current: dict[str, Any], expected_ip: Any, expected_remote: Any) -> bool:
    return (
        normalize_for_compare(current.get("ip")) == normalize_for_compare(expected_ip)
        and normalize_for_compare(current.get("remote-ip")) == normalize_for_compare(expected_remote)
    )


def get_interface_object(
    client: FmgClient,
    device: str,
    interface: str,
    vdom: str | None = None,
) -> dict[str, Any]:
    """Retrieve one system/interface entry using the verified table GET method.

    Some FortiManager versions do not return a normal object payload when the
    interface name is appended to the system/interface URL. Discovery already
    succeeds by reading the complete table with ``verbose=1``. Revalidation,
    read-back, and rollback therefore use the same table request and select the
    required entry locally by interface name and VDOM.
    """
    rows = get_system_interfaces(client, device)

    if vdom is not None:
        matched = find_interface(rows, interface, vdom)
        if matched is not None:
            return matched

        same_name = [
            row for row in rows
            if str(row.get("name", "")) == interface
        ]
        found_vdoms = sorted({interface_vdom(row) for row in same_name})
        detail = (
            f" Found the name in VDOM(s): {', '.join(found_vdoms)}."
            if found_vdoms
            else " Interface name was not found in the returned table."
        )
        raise ToolError(
            f"Unable to retrieve interface {device}/{vdom}/{interface}." + detail
        )

    same_name = [
        row for row in rows
        if str(row.get("name", "")) == interface
    ]
    if len(same_name) == 1:
        return same_name[0]
    if not same_name:
        raise ToolError(
            f"Unable to retrieve interface {device}/{interface}: "
            "interface name was not found in the returned table."
        )

    found_vdoms = sorted({interface_vdom(row) for row in same_name})
    raise ToolError(
        f"Unable to retrieve unique interface {device}/{interface}: "
        f"the name exists in multiple VDOMs ({', '.join(found_vdoms)})."
    )




def apply_changes(
    client: FmgClient,
    adom: str,
    allocations: list[Allocation],
    output_dir: Path,
    *,
    batch_size: int,
    workspace_mode: str = "off",
) -> None:
    changes = change_records(allocations)
    rollback_path = write_rollback(output_dir, client.host, adom, changes)
    print(f"[OK] Rollback data saved to {rollback_path}")

    # FortiManager API device-level changes under /pm/config/device/... do not
    # require an ADOM workspace lock. The workspace_mode argument is retained
    # only for backward compatibility with v3 command lines.
    if workspace_mode != "off":
        print(
            "[INFO] --workspace is ignored for this operation; "
            "device-level API changes do not require an ADOM lock."
        )

    # Revalidate immediately before updating so the plan cannot silently apply
    # to interfaces that changed after discovery.
    print("[INFO] Revalidating target interfaces...")
    for change in changes:
        current = get_interface_object(
            client,
            change["device"],
            change["interface"],
            change["vdom"],
        )
        current_vdom = interface_vdom(current)
        if current_vdom != change["vdom"]:
            raise ToolError(
                f"VDOM changed for {change['device']}/{change['interface']}: "
                f"expected {change['vdom']}, found {current_vdom}."
            )
        if not is_tunnel_interface(current):
            raise ToolError(
                f"Interface {change['device']}/{change['interface']} "
                "is no longer a tunnel interface."
            )
        if not values_match(current, change.get("old_ip"), change.get("old_remote_ip")):
            raise ToolError(
                f"Interface values changed after planning: "
                f"{change['device']}/{change['interface']}. Run discovery again."
            )

    print(f"[INFO] Updating {len(changes)} interface objects in batches of {batch_size}...")
    for start in range(0, len(changes), batch_size):
        batch = changes[start : start + batch_size]
        params = [
            {
                "url": interface_object_url(change["device"], change["interface"]),
                "data": {
                    "ip": change["new_ip"],
                    "remote-ip": change["new_remote_ip"],
                },
            }
            for change in batch
        ]
        client.update_batch(params)
        print(f"  [OK] Updated {min(start + len(batch), len(changes))}/{len(changes)} interfaces")

    print("[INFO] Reading back changed interface objects...")
    failures: list[str] = []
    for change in changes:
        current = get_interface_object(
            client,
            change["device"],
            change["interface"],
            change["vdom"],
        )
        if not values_match(current, change["new_ip"], change["new_remote_ip"]):
            failures.append(
                f"{change['device']}/{change['interface']}: "
                f"expected {change['new_ip']}, {change['new_remote_ip']}; "
                f"found {current.get('ip')!r}, {current.get('remote-ip')!r}"
            )
    if failures:
        raise ToolError("Read-back verification failed:\n  " + "\n  ".join(failures))

    print(f"[OK] Read-back verification passed for {len(changes)} interfaces.")
    print("[OK] FortiManager Device Database updated successfully.")
    print("[INFO] No configuration was installed to FortiGate devices.")

def rollback_changes(
    client: FmgClient,
    rollback_file: Path,
    *,
    batch_size: int,
    workspace_mode: str = "off",
    assume_yes: bool,
) -> None:
    """Restore the previous tunnel-interface values through the FMG API.

    The rollback is intentionally conservative. It refuses to overwrite an
    interface when its current values no longer match the values that the apply
    operation recorded as new_ip/new_remote_ip. This protects later administrator
    changes from a stale rollback file.
    """
    try:
        payload = json.loads(rollback_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError(f"Unable to read rollback file: {exc}") from exc

    adom = str(payload.get("adom", "")).strip()
    changes = payload.get("changes")
    if not adom or not isinstance(changes, list) or not changes:
        raise ToolError("Rollback file is missing adom or changes.")

    required_fields = {
        "device",
        "vdom",
        "interface",
        "new_ip",
        "new_remote_ip",
    }
    for index, change in enumerate(changes, start=1):
        if not isinstance(change, dict):
            raise ToolError(f"Rollback change #{index} is not a JSON object.")
        missing = required_fields.difference(change)
        if missing:
            raise ToolError(
                f"Rollback change #{index} is missing: "
                + ", ".join(sorted(missing))
            )

    print(f"Rollback ADOM: {adom}")
    print(f"Interfaces to restore: {len(changes)}")

    if workspace_mode != "off":
        print(
            "[INFO] --workspace is ignored for rollback; "
            "device-level API changes do not use an ADOM lock."
        )

    if not assume_yes:
        answer = input(
            "Type ROLLBACK to restore the previous FMG Device Database values: "
        ).strip()
        if answer != "ROLLBACK":
            raise ToolError("Rollback cancelled.")

    print("[INFO] Revalidating rollback targets...")
    for change in changes:
        device = str(change["device"])
        vdom = str(change.get("vdom") or "root")
        interface_name = str(change["interface"])

        current = get_interface_object(client, device, interface_name, vdom)
        current_vdom = interface_vdom(current)
        if current_vdom != vdom:
            raise ToolError(
                f"Rollback target VDOM mismatch for {device}/{interface_name}: "
                f"expected {vdom}, found {current_vdom}."
            )
        if not is_tunnel_interface(current):
            raise ToolError(
                f"Rollback target {device}/{interface_name} is not a tunnel interface."
            )
        if not values_match(
            current,
            change.get("new_ip"),
            change.get("new_remote_ip"),
        ):
            current_ip = normalize_cidr(current.get("ip")) or "unset"
            current_remote = normalize_cidr(current.get("remote-ip")) or "unset"
            expected_ip = normalize_cidr(change.get("new_ip")) or "unset"
            expected_remote = normalize_cidr(change.get("new_remote_ip")) or "unset"
            raise ToolError(
                f"Refusing rollback for {device}/{interface_name}: current values "
                "do not match the values written by this plan.\n"
                f"  Expected current ip: {expected_ip}\n"
                f"  Actual current ip: {current_ip}\n"
                f"  Expected current remote-ip: {expected_remote}\n"
                f"  Actual current remote-ip: {current_remote}\n"
                "Another change may have occurred after apply."
            )
        print(f"  [OK] {device}/{vdom}/{interface_name}")

    print("[INFO] Restoring previous interface values...")
    for start in range(0, len(changes), batch_size):
        batch = changes[start : start + batch_size]
        params: list[dict[str, Any]] = []
        for change in batch:
            old_ip = normalize_cidr(change.get("old_ip")) or "0.0.0.0/0"
            old_remote = (
                normalize_cidr(change.get("old_remote_ip")) or "0.0.0.0/0"
            )
            params.append(
                {
                    "url": interface_object_url(
                        str(change["device"]),
                        str(change["interface"]),
                    ),
                    "data": {
                        "ip": old_ip,
                        "remote-ip": old_remote,
                    },
                }
            )
        client.update_batch(params)
        print(
            f"  [OK] Restored "
            f"{min(start + len(batch), len(changes))}/{len(changes)} interfaces"
        )

    print("[INFO] Verifying restored values...")
    failures: list[str] = []
    for change in changes:
        device = str(change["device"])
        vdom = str(change.get("vdom") or "root")
        interface_name = str(change["interface"])
        current = get_interface_object(client, device, interface_name, vdom)

        if interface_vdom(current) != vdom:
            failures.append(
                f"{device}/{interface_name}: expected VDOM {vdom}, "
                f"found {interface_vdom(current)}"
            )
            continue
        if not values_match(
            current,
            change.get("old_ip"),
            change.get("old_remote_ip"),
        ):
            actual_ip = normalize_cidr(current.get("ip")) or "unset"
            actual_remote = normalize_cidr(current.get("remote-ip")) or "unset"
            expected_ip = normalize_cidr(change.get("old_ip")) or "unset"
            expected_remote = normalize_cidr(change.get("old_remote_ip")) or "unset"
            failures.append(
                f"{device}/{interface_name}: expected {expected_ip}, "
                f"{expected_remote}; found {actual_ip}, {actual_remote}"
            )
            continue
        print(f"  [OK] {device}/{vdom}/{interface_name}")

    if failures:
        raise ToolError(
            "Rollback read-back verification failed:\n  "
            + "\n  ".join(failures)
        )

    print(f"[OK] Rollback verification passed for {len(changes)} interfaces.")
    print("[OK] Previous values restored in the FortiManager Device Database.")
    print("[INFO] No configuration was installed to FortiGate devices.")

def load_configuration(args: argparse.Namespace) -> tuple[str, str, bool, int]:
    config = configparser.ConfigParser()
    config_path: Path | None = None
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            raise ToolError(f"Configuration file not found: {config_path}")
    else:
        for candidate in DEFAULT_CONFIG_FILES:
            path = Path(candidate)
            if path.exists():
                config_path = path
                break
    if config_path:
        config.read(config_path, encoding="utf-8")

    section = config["fortimanager"] if config.has_section("fortimanager") else {}
    host = args.host or section.get("host") or ""
    api_key = args.api_key or section.get("api_key") or section.get("token") or ""
    verify_ssl_text = str(section.get("verify_ssl", "true")).strip().lower()
    verify_ssl = verify_ssl_text not in {"0", "false", "no", "off"}
    if args.no_verify_ssl:
        verify_ssl = False
    timeout = args.timeout or int(section.get("timeout", 30))

    if not host:
        host = input("FortiManager URL or IP: ").strip()
    if not api_key:
        import getpass

        api_key = getpass.getpass("FortiManager API token: ").strip()
    if not host or not api_key:
        raise ToolError("FortiManager host and API token are required.")
    return host, api_key, verify_ssl, timeout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Assign numbered tunnel-interface IPs to a FortiManager VPN Manager community.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--config", help="INI configuration file")
    parser.add_argument("--host", help="FortiManager URL or IP")
    parser.add_argument("--api-key", help="FortiManager API token (prefer config.ini or prompt)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--timeout", type=int, default=None, help="HTTPS timeout in seconds")
    parser.add_argument("--adom", help="ADOM name")
    parser.add_argument("--community", help="VPN Manager community name")
    parser.add_argument("--tunnel-regex", help="Regex used to match Phase 1 names")
    parser.add_argument("--gateway-map", help="JSON file containing local public gateway overrides")
    parser.add_argument("--pool", help="IPv4 CIDR pool to split into /30 networks")
    parser.add_argument("--apply", action="store_true", help="Update the FortiManager Device Database")
    parser.add_argument(
        "--overwrite-existing",
        action="store_true",
        help="Treat partial/conflicting existing tunnel addressing as eligible (dangerous)",
    )
    parser.add_argument("--yes", action="store_true", help="Do not prompt for apply/rollback confirmation")
    parser.add_argument("--export-dir", help="Directory for plan, CSV, and rollback files")
    parser.add_argument("--export", action="store_true", help="Export dry-run plan files")
    parser.add_argument("--batch-size", type=int, default=50, help="Maximum interface updates per API request")
    parser.add_argument(
        "--workspace",
        choices=("auto", "on", "off"),
        default="off",
        help=(
            "Deprecated compatibility option. Device-level API changes do not "
            "use an ADOM workspace lock."
        ),
    )
    parser.add_argument("--rollback", help="Restore values from a rollback.json file")
    parser.add_argument("--allow-unresolved", action="store_true", help="Allow apply when unrelated endpoints are unresolved")
    parser.add_argument("--debug", action="store_true", help="Print JSON API requests and responses")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    print(f"FMG VPN Tunnel IP Tool - {TOOL_VERSION}")
    args = build_parser().parse_args(argv)
    if args.batch_size < 1 or args.batch_size > 500:
        raise ToolError("--batch-size must be between 1 and 500.")

    host, api_key, verify_ssl, timeout = load_configuration(args)
    client = FmgClient(host, api_key, verify_ssl=verify_ssl, timeout=timeout, debug=args.debug)

    if args.rollback:
        rollback_changes(
            client,
            Path(args.rollback),
            batch_size=args.batch_size,
            workspace_mode=args.workspace,
            assume_yes=args.yes,
        )
        return 0

    # Connectivity/version check is informational because response fields differ by FMG release.
    try:
        status = client.get("/sys/status")
        if isinstance(status, dict):
            version = get_any(status, "Version", "version", "build", default="")
            print(f"Connected to FortiManager {version}".rstrip())
        else:
            print("Connected to FortiManager.")
    except FmgApiError:
        # A restricted API admin may not have /sys/status permission; continue to ADOM discovery.
        print("Connected to FortiManager (system status not available to this API administrator).")

    adoms = get_adoms(client)
    adom_row = choose_item(
        "ADOMs",
        adoms,
        lambda row: (
            f"{row.get('name', '?')}  "
            f"Product={adom_product_code(row)}  "
            f"FortiOS={get_any(row, 'os_ver', 'os-ver', default='?')}"
        ),
        args.adom,
    )
    adom = str(adom_row["name"])

    devices = get_devices(client, adom)
    groups = get_groups(client, adom)
    print_devices_and_groups(devices, groups)
    devices_by_name = {str(item.get("name", "")): item for item in devices}
    groups_by_name = {str(item.get("name", "")): item for item in groups}

    communities = get_communities(client, adom)
    community_row = choose_item(
        "VPN communities",
        communities,
        lambda row: f"{row.get('name', '?'):<20} topology={row.get('topology', '?')}  {row.get('description', '')}",
        args.community,
    )
    community_name = str(community_row["name"])
    topology = str(community_row.get("topology", ""))
    print(f"\nSelected community: {community_name} ({topology or 'unknown topology'})")

    nodes = get_vpn_nodes(client, adom)
    members, member_warnings = community_members(
        nodes,
        community_name,
        devices_by_name,
        groups_by_name,
    )
    print_members(members)
    for warning in member_warnings:
        print(f"[WARN] {warning}")
    if not members:
        raise ToolError("No direct device/VDOM members were resolved for the selected community.")

    default_regex = rf"^{re.escape(community_name)}_[0-9]+$"
    regex_text = args.tunnel_regex or default_regex
    try:
        tunnel_pattern = re.compile(regex_text)
    except re.error as exc:
        raise ToolError(f"Invalid tunnel regex '{regex_text}': {exc}") from exc
    print(f"Tunnel name regex: {regex_text}")

    gateway_overrides = load_json_file(args.gateway_map)
    endpoints, unresolved, interface_cache = discover_endpoints(
        client,
        members,
        tunnel_pattern,
        gateway_overrides,
    )
    print(f"\nCandidate tunnel endpoints: {len(endpoints)}")
    for endpoint in endpoints:
        print(
            f"  - {endpoint.key.text():<70} "
            f"local={','.join(endpoint.local_gateways):<20} remote={endpoint.remote_gw}"
        )

    pairs, pairing_unresolved = pair_endpoints(endpoints)
    unresolved.extend(pairing_unresolved)
    validate_pairs(pairs)
    print_pair_summary(pairs)
    print_unresolved(unresolved)

    eligible = [pair for pair in pairs if pair.status == "eligible"]
    conflicts = [pair for pair in pairs if pair.status in {"partial", "conflict"}]
    if args.overwrite_existing:
        for pair in conflicts:
            pair.status = "eligible"
            pair.reason = "Existing values will be overwritten by explicit operator request."
        eligible.extend(conflicts)
        print(f"[WARN] --overwrite-existing enabled: {len(conflicts)} conflicting/partial pairs will be replaced.")

    if args.apply and unresolved and not args.allow_unresolved:
        raise ToolError(
            "Unresolved endpoints exist. Resolve them or use --allow-unresolved to apply only confirmed pairs."
        )
    if args.apply and conflicts and not args.overwrite_existing:
        raise ToolError("Partial or conflicting tunnel addressing exists. Resolve it before using --apply.")

    allocations: list[Allocation] = []
    pool: ipaddress.IPv4Network | None = None
    skipped_subnets = 0
    if eligible:
        pool = get_pool_from_user(args.pool)
        used_networks = collect_used_networks(interface_cache)
        subnets, skipped_subnets = available_subnets(pool, used_networks, len(eligible))
        allocations = allocate_pairs(eligible, subnets)
        print(f"\nAddress pool: {pool}")
        print(f"Required /30 networks: {len(eligible)}")
        print(f"Overlapping /30 networks skipped before completing allocation: {skipped_subnets}")
        print_plan(allocations)
    else:
        print("\nNo eligible tunnel pairs require new addressing.")

    output_dir: Path | None = None
    if args.export or args.apply:
        output_dir = create_output_dir(args.export_dir, community_name)
        export_results(
            output_dir,
            host=client.host,
            adom=adom,
            community=community_name,
            tunnel_regex=regex_text,
            pool=str(pool) if pool else None,
            allocations=allocations,
            unresolved=unresolved,
            pairs=pairs,
        )
        print(f"[OK] Plan files written to {output_dir.resolve()}")

    if not args.apply:
        print("\n[DRY RUN] No FortiManager configuration was changed.")
        return 0
    if not allocations:
        print("[INFO] Nothing to apply.")
        return 0

    if not args.yes:
        answer = input("\nType APPLY to update the FortiManager Device Database: ").strip()
        if answer != "APPLY":
            raise ToolError("Apply cancelled.")

    assert output_dir is not None
    apply_changes(
        client,
        adom,
        allocations,
        output_dir,
        batch_size=args.batch_size,
        workspace_mode=args.workspace,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        raise SystemExit(130)
    except ToolError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
