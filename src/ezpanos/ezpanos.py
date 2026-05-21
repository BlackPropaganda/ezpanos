import urllib
import requests
import getpass
import ipaddress
import os

from urllib3.exceptions import InsecureRequestWarning
import re
import json
import tempfile
import time
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET
from copy import deepcopy

from ezpanos.utils import *
from ezpanos.models import PanosConfig
from ezpanos.factories import *
from ezpanos.command_parser import parse_command_to_xml

"""
PanOS API integration
"""


class AuthenticationError(RuntimeError):
    """Raised when PAN-OS authentication or API key generation fails."""


def prettyprint_xml(xml_str: str, shorten=True) -> None:
    """
    Pretty prints an XML string in a tabular format, showing each tag and its content.

    Args:
        xml_str (str): XML string to pretty print.
    """
    # this method needs a lint roller... Fuzzy beast.
    def print_element(element, indent=0):
        prefix = "  " * indent
        if list(element):
            print(f"{prefix}{element.tag}:")
            for child in element:
                print_element(child, indent + 1)
        else:
            text = element.text.strip() if element.text else ""
            print(f"{prefix}{element.tag}: {text}")

    from xml.etree import ElementTree as ET
    # default response is always <response><result>...</result></response>
    # If shorten is True, only print the contents of <result> or <msg> if present
    try:
        root = ET.fromstring(xml_str)
        if shorten:
            # Try to find <result> or <msg> under <response>
            result = root.find("result")
            msg = root.find("msg")
            if result is not None:
                print_element(result)
                return
            elif msg is not None:
                print("Error Message:")
                print_element(msg)
                return
    except Exception:
        pass  # Fallback to full pretty print if parsing fails

    try:
        root = ET.fromstring(xml_str)
        print_element(root)
    except Exception as e:
        print("Failed to parse XML:", e)


def is_network_location(ip_address: str) -> bool:
    """
    Determines if the given IP address is a network location (i.e., matches regex).

    Args:
        ip_address (str): The IP address to check.
    Returns:
        bool: True if it's a network location, False otherwise.
    """
    # Regex for IPv4 address
    ip_pattern = r"^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}"
    fqdn_pattern = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?"
    return (
        re.match(ip_pattern, ip_address) is not None
    ) or (
        re.match(fqdn_pattern, ip_address) is not None
    )


def build_xml_from_command(command_str: str) -> str:
    """
    Convert a plaintext PAN-OS CLI command into XML API command payload.

    The heavy-lifting parser is implemented in the dedicated command parser
    subsystem so parsing rules can evolve independently from API execution.
    """
    return parse_command_to_xml(command_str)


class EzPanOS:
    @staticmethod
    def _normalize_api_key(value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            return None
        normalized = value.strip()
        if not normalized:
            return None
        if normalized.lower() in {"none", "null", "nil", "n/a", "na"}:
            return None
        return normalized

    @staticmethod
    def _coalesce_config_string(block: dict, *keys: str) -> str | None:
        for key in keys:
            value = block.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _normalize_credential(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip()
        return normalized or None

    @staticmethod
    def _load_config_data(config_path: str) -> dict:
        config_file = Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"config file not found: {config_path}")

        with config_file.open("r", encoding="utf-8") as in_file:
            data = json.load(in_file)

        if not isinstance(data, dict):
            raise ValueError("config file must contain a top-level JSON object")

        return data

    @staticmethod
    def _resolve_config_block(config_data: dict, endpoint: str | None, config_profile: str | None) -> dict:
        if config_profile:
            profiles = config_data.get("profiles")
            if not isinstance(profiles, dict):
                raise ValueError("config has no `profiles` object")

            selected = profiles.get(config_profile)
            if not isinstance(selected, dict):
                raise ValueError(f"profile `{config_profile}` not found in config")
            return selected

        endpoint_map = config_data.get("endpoints")
        if endpoint and isinstance(endpoint_map, dict):
            selected = endpoint_map.get(endpoint)
            if isinstance(selected, dict):
                return selected

        return config_data

    @staticmethod
    def _normalize_profile_endpoint_entries(config_block: dict) -> list[dict]:
        """
        Returns normalized endpoint records from a profile block.

        Supported shapes:
        - Single endpoint profile:
          {"endpoint": "...", "username": "...", "password": "..."}
        - Multi-endpoint list:
          {"endpoints": [{"endpoint": "..."}, ...]}
        - Multi-endpoint map:
          {"endpoints": {"10.0.6.2": {"username": "...", "password": "..."}, ...}}
        """
        endpoint_entries = config_block.get("endpoints")
        out: list[dict] = []

        if isinstance(endpoint_entries, list):
            for entry in endpoint_entries:
                if not isinstance(entry, dict):
                    continue
                out.append(entry)
            return out

        if isinstance(endpoint_entries, dict):
            for endpoint_name, entry in endpoint_entries.items():
                if isinstance(entry, dict):
                    merged = {"endpoint": str(endpoint_name)}
                    merged.update(entry)
                    out.append(merged)
            return out

        # Fallback: treat profile itself as a single endpoint entry when no `endpoints` list/map exists.
        has_single_endpoint = isinstance(config_block.get("endpoint"), str) or isinstance(config_block.get("firewall_endpoint"), str)
        if has_single_endpoint:
            out.append(config_block)
        return out

    @staticmethod
    def _deep_merge_dict(base: dict | None, overlay: dict | None) -> dict:
        """
        Recursively merge two dictionaries without mutating inputs.
        """
        merged = deepcopy(base) if isinstance(base, dict) else {}
        if not isinstance(overlay, dict):
            return merged

        for key, value in overlay.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = EzPanOS._deep_merge_dict(merged.get(key), value)
            else:
                merged[key] = deepcopy(value)
        return merged

    @classmethod
    def _resolve_policy_defaults_for_endpoint(cls, config_block: dict, endpoint: str | None) -> dict:
        """
        Build effective policy defaults from profile-level and endpoint-level blocks.
        """
        effective = {}
        if not isinstance(config_block, dict):
            return effective

        effective = cls._deep_merge_dict(effective, config_block.get("policy_defaults"))
        endpoint_text = str(endpoint).strip() if endpoint is not None else None
        if not endpoint_text:
            return effective

        for entry in cls._normalize_profile_endpoint_entries(config_block):
            if not isinstance(entry, dict):
                continue
            entry_endpoint = cls._coalesce_config_string(entry, "endpoint", "firewall_endpoint")
            if not entry_endpoint:
                continue
            if str(entry_endpoint).strip() != endpoint_text:
                continue
            effective = cls._deep_merge_dict(effective, entry.get("policy_defaults"))
            break

        return effective

    @classmethod
    def _resolve_api_defaults_for_endpoint(cls, config_block: dict, endpoint: str | None) -> dict:
        """
        Build effective API defaults from profile-level and endpoint-level blocks.

        Supported shape:
        {
          "api_defaults": {"request_timeout": 60, "keygen_timeout": 30},
          "endpoints": [
            {"endpoint": "10.0.0.1", "api_defaults": {"request_timeout": 90}}
          ]
        }
        """
        effective = {}
        if not isinstance(config_block, dict):
            return effective

        effective = cls._deep_merge_dict(effective, config_block.get("api_defaults"))
        endpoint_text = str(endpoint).strip() if endpoint is not None else None
        if not endpoint_text:
            return effective

        for entry in cls._normalize_profile_endpoint_entries(config_block):
            if not isinstance(entry, dict):
                continue
            entry_endpoint = cls._coalesce_config_string(entry, "endpoint", "firewall_endpoint")
            if not entry_endpoint:
                continue
            if str(entry_endpoint).strip() != endpoint_text:
                continue
            effective = cls._deep_merge_dict(effective, entry.get("api_defaults"))
            break

        return effective

    @staticmethod
    def _coerce_positive_timeout(value: Any, default: float) -> float:
        try:
            candidate = float(value)
            if candidate <= 0:
                raise ValueError
            return candidate
        except (TypeError, ValueError):
            return float(default)

    @staticmethod
    def _coerce_bool(value: Any, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "y", "on"}:
                return True
            if normalized in {"0", "false", "no", "n", "off"}:
                return False
        return bool(default)

    @classmethod
    def _resolve_timeout_setting(
        cls,
        explicit_value: Any,
        env_var: str,
        config_block: dict | None,
        config_key: str,
        default: float,
    ) -> float:
        if explicit_value is not None:
            return cls._coerce_positive_timeout(explicit_value, default=default)

        env_raw = os.getenv(env_var, "").strip()
        if env_raw:
            return cls._coerce_positive_timeout(env_raw, default=default)

        config_value = None
        if isinstance(config_block, dict):
            config_value = config_block.get(config_key)
        return cls._coerce_positive_timeout(config_value, default=default)

    @staticmethod
    def _extract_payload_scalar(value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, (str, int, float)):
            text = str(value).strip()
            return text or None
        if isinstance(value, dict):
            for key in ("_text", "name", "serial", "id", "value"):
                candidate = value.get(key)
                if isinstance(candidate, (str, int, float)):
                    text = str(candidate).strip()
                    if text:
                        return text
        return None

    @classmethod
    def _coalesce_payload_string(cls, payload: dict, *keys: str) -> str | None:
        if not isinstance(payload, dict):
            return None
        for key in keys:
            if key not in payload:
                continue
            text = cls._extract_payload_scalar(payload.get(key))
            if text:
                return text
        return None

    @classmethod
    def _find_first_payload_string(cls, payload: Any, *keys: str) -> str | None:
        if isinstance(payload, dict):
            direct = cls._coalesce_payload_string(payload, *keys)
            if direct:
                return direct
            for value in payload.values():
                nested = cls._find_first_payload_string(value, *keys)
                if nested:
                    return nested
        elif isinstance(payload, list):
            for item in payload:
                nested = cls._find_first_payload_string(item, *keys)
                if nested:
                    return nested
        return None

    @classmethod
    def _iter_entries_for_parent_keys(cls, payload: Any, parent_keys: set[str]) -> list[dict]:
        out = []

        def walk(node: Any, parent_key: str | None = None) -> None:
            if isinstance(node, dict):
                normalized_parent = str(parent_key or "").strip().lower()
                if normalized_parent in parent_keys:
                    entries = node.get("entry")
                    for entry in ensure_list(entries):
                        if isinstance(entry, dict):
                            out.append(entry)

                for key, value in node.items():
                    walk(value, str(key).strip().lower())
            elif isinstance(node, list):
                for item in node:
                    walk(item, parent_key)

        walk(payload, None)
        return out

    @classmethod
    def _parse_panorama_managed_devices(cls, payload: dict | None) -> list[dict]:
        if not isinstance(payload, dict):
            return []

        candidates = cls._iter_entries_for_parent_keys(
            payload,
            {
                "devices",
                "firewalls",
                "managed-devices",
                "managed_devices",
            },
        )

        managed = []
        seen = set()
        for entry in candidates:
            serial = cls._coalesce_payload_string(entry, "serial", "name", "deviceid", "device-id")
            hostname = cls._coalesce_payload_string(entry, "hostname", "host-name", "devicename", "device-name")
            endpoint = cls._coalesce_payload_string(
                entry,
                "ip-address",
                "ip_address",
                "management-ip",
                "management_ip",
                "mgmt-ip",
                "mgmt_ip",
            )
            connected_raw = cls._coalesce_payload_string(entry, "connected", "state", "status")
            connected = None
            if connected_raw is not None:
                connected = connected_raw.strip().lower() in {"yes", "true", "up", "connected", "active"}

            if not serial and not hostname and not endpoint:
                continue

            identity = (serial or "", endpoint or "", hostname or "")
            if identity in seen:
                continue
            seen.add(identity)

            managed.append(
                {
                    "serial": serial,
                    "hostname": hostname,
                    "endpoint": endpoint,
                    "connected": connected,
                    "raw": entry,
                }
            )

        return managed

    @classmethod
    def _extract_device_members(cls, payload: Any) -> list[str]:
        out = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                members = node.get("member")
                if members is not None:
                    for member in ensure_list(members):
                        text = cls._extract_payload_scalar(member)
                        if text:
                            out.append(text)

                entries = node.get("entry")
                if entries is not None:
                    for entry in ensure_list(entries):
                        if isinstance(entry, dict):
                            text = cls._coalesce_payload_string(entry, "serial", "name", "deviceid", "device-id")
                            if text:
                                out.append(text)

                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)
        return list(dict.fromkeys([member for member in out if member]))

    @classmethod
    def _parse_panorama_device_groups(cls, payload: dict | None) -> dict[str, list[str]]:
        if not isinstance(payload, dict):
            return {}

        device_groups = cls._iter_entries_for_parent_keys(payload, {"devicegroups", "device-groups"})
        group_map: dict[str, list[str]] = {}

        for group_entry in device_groups:
            group_name = cls._coalesce_payload_string(group_entry, "name")
            if not group_name:
                continue

            serials = []
            for key in ("devices", "device"):
                serials.extend(cls._extract_device_members(group_entry.get(key)))
            if not serials:
                continue

            for serial in serials:
                bucket = group_map.setdefault(serial, [])
                if group_name not in bucket:
                    bucket.append(group_name)

        return group_map

    @classmethod
    def _parse_panorama_template_assignments(cls, payload: dict | None) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        if not isinstance(payload, dict):
            return {}, {}

        templates = cls._iter_entries_for_parent_keys(payload, {"templates", "template"})
        template_stacks = cls._iter_entries_for_parent_keys(payload, {"template-stack", "template-stacks", "template_stack"})

        templates_by_serial: dict[str, list[str]] = {}
        template_stacks_by_serial: dict[str, list[str]] = {}

        for template_entry in templates:
            template_name = cls._coalesce_payload_string(template_entry, "name")
            if not template_name:
                continue
            serials = []
            for key in ("devices", "device"):
                serials.extend(cls._extract_device_members(template_entry.get(key)))
            for serial in serials:
                bucket = templates_by_serial.setdefault(serial, [])
                if template_name not in bucket:
                    bucket.append(template_name)

        for stack_entry in template_stacks:
            stack_name = cls._coalesce_payload_string(stack_entry, "name")
            if not stack_name:
                continue
            serials = []
            for key in ("devices", "device"):
                serials.extend(cls._extract_device_members(stack_entry.get(key)))
            for serial in serials:
                bucket = template_stacks_by_serial.setdefault(serial, [])
                if stack_name not in bucket:
                    bucket.append(stack_name)

        return templates_by_serial, template_stacks_by_serial

    @classmethod
    def _build_estate_id(
        cls,
        endpoint: str | None,
        role: str = "firewall",
        controller_id: str | None = None,
        serial: str | None = None,
        profile: str | None = None,
        entry_index: int | None = None,
    ) -> str:
        endpoint_text = str(endpoint).strip() if endpoint is not None else "unknown-endpoint"
        if role == "firewall" and (not controller_id) and (serial is None) and (profile is None) and (entry_index is None):
            return endpoint_text

        parts = [
            f"role={role}",
            f"endpoint={endpoint_text}",
        ]
        if controller_id:
            parts.append(f"controller={str(controller_id).strip()}")
        if serial:
            parts.append(f"serial={str(serial).strip()}")
        if profile:
            parts.append(f"profile={str(profile).strip()}")
        if entry_index is not None:
            parts.append(f"entry={int(entry_index)}")
        return "|".join(parts)

    @classmethod
    def _looks_like_panorama_entry(cls, entry: dict, profile_block: dict | None = None) -> bool:
        role = cls._coalesce_config_string(entry, "role", "device_type", "type")
        role_normalized = str(role or "").strip().lower()
        if role_normalized in {"panorama", "panorama-controller", "controller"}:
            return True

        if cls._coerce_bool(entry.get("is_panorama"), default=False):
            return True

        explicit = entry.get("discover_panorama_managed")
        if explicit is None:
            explicit = entry.get("discover_managed_devices")
        if explicit is None:
            explicit = entry.get("panorama_discovery")
        if explicit is not None:
            return cls._coerce_bool(explicit, default=False)

        if isinstance(profile_block, dict):
            profile_role = cls._coalesce_config_string(profile_block, "role", "device_type", "type")
            profile_role_normalized = str(profile_role or "").strip().lower()
            if profile_role_normalized in {"panorama", "panorama-controller", "controller"}:
                return True
            if cls._coerce_bool(profile_block.get("discover_panorama_managed"), default=False):
                return True
            if cls._coerce_bool(profile_block.get("discover_managed_devices"), default=False):
                return True
            if cls._coerce_bool(profile_block.get("panorama_discovery"), default=False):
                return True

        return False

    @classmethod
    def _entry_auth_tuple(
        cls,
        entry: dict,
        default_username: str | None,
        default_password: str | None,
    ) -> tuple[str | None, str | None]:
        username = cls._coalesce_config_string(entry, "username", "user") or default_username
        password = cls._coalesce_config_string(entry, "password")
        if password is None:
            password = default_password

        return username, password

    @classmethod
    def _build_instance_from_profile_entry(
        cls,
        entry: dict,
        config_path: str,
        config_profile: str,
        default_username: str | None,
        default_password: str | None,
        connect_on_init: bool,
    ) -> tuple[str | None, Any]:
        endpoint = cls._coalesce_config_string(entry, "endpoint", "firewall_endpoint")
        if not endpoint:
            return None, None

        username, password = cls._entry_auth_tuple(
            entry=entry,
            default_username=default_username,
            default_password=default_password,
        )

        instance = cls(
            endpoint=endpoint,
            username=username,
            password=password,
            config_path=config_path,
            config_profile=config_profile,
            connect_on_init=connect_on_init,
            fail_on_init_error=False,
        )
        return endpoint, instance

    @classmethod
    def request_api_key(
        cls,
        endpoint: str,
        username: str,
        password: str,
        request_timeout: int | float = 30,
    ) -> str | None:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        params = {
            "type": "keygen",
            "user": username,
            "password": password,
        }
        url = f"https://{endpoint}/api?{urllib.parse.urlencode(params)}"

        try:
            timeout = cls._coerce_positive_timeout(request_timeout, default=30.0)
            response = requests.get(url, verify=False, timeout=timeout)
            response.raise_for_status()
            root = ET.fromstring(response.text)
            key = root.findtext(".//key")
            if isinstance(key, str) and key.strip():
                return key.strip()
        except Exception:
            return None

        return None

    @classmethod
    def prompt_and_request_api_key(
        cls,
        endpoint: str,
        username: str | None = None,
        password: str | None = None,
        request_timeout: int | float = 30,
    ) -> str:
        """
        Prompt securely for missing credentials and return a generated API key.
        """
        if not username:
            username = input("Username: ")
        if password is None:
            password = getpass.getpass("Password: ")

        api_key = cls.request_api_key(
            endpoint=endpoint,
            username=username,
            password=password,
            request_timeout=request_timeout,
        )
        if not api_key:
            raise AuthenticationError("Failed to generate API key from provided credentials.")
        return api_key

    @classmethod
    def _prompt_for_missing_credentials(
        cls,
        username: str | None,
        password: str | None,
    ) -> tuple[str, str]:
        resolved_username = cls._normalize_credential(username)
        resolved_password = cls._normalize_credential(password)

        while resolved_username is None:
            entered_username = cls._normalize_credential(input("Username: "))
            if entered_username:
                resolved_username = entered_username

        while resolved_password is None:
            entered_password = cls._normalize_credential(getpass.getpass("Password: "))
            if entered_password:
                resolved_password = entered_password

        return resolved_username, resolved_password

    @classmethod
    def _request_api_key_or_raise(
        cls,
        endpoint: str,
        username: str,
        password: str,
        request_timeout: int | float,
    ) -> str:
        api_key = cls.request_api_key(
            endpoint=endpoint,
            username=username,
            password=password,
            request_timeout=request_timeout,
        )
        normalized_key = cls._normalize_api_key(api_key)
        if not normalized_key:
            raise AuthenticationError(
                f"Authentication failed while generating API key for endpoint {endpoint}."
            )
        return normalized_key

    def __init__(
        self,
        endpoint=None,
        username=None,
        password=None,
        api_key=None,
        config_path=None,
        config_profile=None,
        request_timeout_default: int | float | None = None,
        keygen_request_timeout: int | float | None = None,
        connect_on_init: bool = True,
        fail_on_init_error: bool = False,
    ):
        # Disable warnings about insecure connections
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self.config_path = config_path
        self.config_profile = config_profile
        self.policy_defaults = {}
        self.api_defaults = {}
        config_block = None

        explicit_username = self._normalize_credential(username)
        explicit_password = self._normalize_credential(password)
        config_username = None
        config_password = None

        if config_path:
            config_data = self._load_config_data(config_path)
            config_block = self._resolve_config_block(config_data, endpoint=endpoint, config_profile=config_profile)

            endpoint = endpoint or self._coalesce_config_string(config_block, "endpoint", "firewall_endpoint")
            config_username = self._normalize_credential(self._coalesce_config_string(config_block, "username", "user"))
            config_password = self._normalize_credential(self._coalesce_config_string(config_block, "password"))

        username = explicit_username if explicit_username is not None else config_username
        password = explicit_password if explicit_password is not None else config_password

        api_key = self._normalize_api_key(api_key)

        if endpoint is None:
            raise ValueError("endpoint is required (directly or via config_path profile)")

        self.endpoint = endpoint
        self.username = username
        self.password = password
        self.api_key = api_key
        self.estate_id = self._build_estate_id(endpoint=self.endpoint, role="firewall")
        self.estate_role = "firewall"
        self.panorama_controller_id = None
        self.panorama_controller_endpoint = None
        self.panorama_managed_serial = None
        self.panorama_managed_hostname = None
        self.panorama_device_groups = []
        self.panorama_templates = []
        self.panorama_template_stacks = []

        if isinstance(config_block, dict):
            self.policy_defaults = self._resolve_policy_defaults_for_endpoint(config_block, self.endpoint)
            self.api_defaults = self._resolve_api_defaults_for_endpoint(config_block, self.endpoint)
        self.request_timeout_default = self._resolve_timeout_setting(
            explicit_value=request_timeout_default,
            env_var="EZPANOS_REQUEST_TIMEOUT",
            config_block=self.api_defaults,
            config_key="request_timeout",
            default=30.0,
        )
        self.keygen_request_timeout = self._resolve_timeout_setting(
            explicit_value=keygen_request_timeout,
            env_var="EZPANOS_KEYGEN_TIMEOUT",
            config_block=self.api_defaults,
            config_key="keygen_timeout",
            default=self.request_timeout_default,
        )
        self.panos = None
        self.connected = False
        self.connection_error = None

        if not self.api_key:
            self.username, self.password = self._prompt_for_missing_credentials(
                username=self.username,
                password=self.password,
            )
            self.api_key = self._request_api_key_or_raise(
                endpoint=self.endpoint,
                username=self.username,
                password=self.password,
                request_timeout=self.keygen_request_timeout,
            )

        if connect_on_init:
            self.connect(fail_on_error=fail_on_init_error)

    def _require_api_key(self) -> None:
        self.api_key = self._normalize_api_key(self.api_key)
        if self.api_key:
            return

        if not (isinstance(self.username, str) and self.username and isinstance(self.password, str) and self.password):
            raise RuntimeError(
                "Missing API key for PAN-OS API call. "
                "Provide a valid api_key or username/password for key generation."
            )
        self.api_key = self._request_api_key_or_raise(
            endpoint=self.endpoint,
            username=self.username,
            password=self.password,
            request_timeout=self.keygen_request_timeout,
        )


    def build_object(self) -> object:
        # dataclass is literally dynamically generated
        config = self.get_configuration()
        return dict_to_dataclass('PanOS', config)

    def connect(self, fail_on_error: bool = False) -> bool:
        """
        Attempt to load configuration and initialize the parsed PAN-OS object.
        Returns True on success, False on failure.
        """
        try:
            self.panos = self.build_object()
            self.connected = True
            self.connection_error = None
            return True
        except Exception as exc:
            self.panos = None
            self.connected = False
            self.connection_error = str(exc)
            if fail_on_error:
                raise
            print(f"Warning: failed to connect to {self.endpoint}: {exc}")
            return False

    def ensure_connected(self, fail_on_error: bool = False) -> bool:
        if self.connected and self.panos is not None:
            return True
        return self.connect(fail_on_error=fail_on_error)

    def _resolve_request_timeout(self, request_timeout: int | float | None) -> float:
        if request_timeout is None:
            return self._coerce_positive_timeout(self.request_timeout_default, default=30.0)
        return self._coerce_positive_timeout(request_timeout, default=self.request_timeout_default)

    def execute(
        self,
        command: str = "",
        api_type: str = "op",
        api_action: str | None = None,
        api_xpath: str | None = None,
        api_cmd: str | None = None,
        api_element: str | None = None,
        api_params: dict | None = None,
        request_timeout: int | float | None = None,
    ) -> dict | None:
        """
        Execute Command.

        This command can execute arbitrary commands on the target firewall when authenticated.

        Supports string and XML commands.

        String commands tested for PanOS base Version 11.1

        :param self: PanOS Object
        :param command: PanOS CLI command string to execute for op calls
        :type command: str
        :param api_type: op (operational) | config | export
        :type api_type: str
        :param api_action: API action (for config calls e.g. get, set, edit)
        :param api_xpath: API xpath (for config calls)
        :return: dict of XML returned by the XML API or None if something fails.
        """
        try:
            self._require_api_key()
            headers = {
                "Content-Type": "application/xml"
            }
            params = {
                "type": api_type,
                "key": self.api_key
            }

            xml_cmd = None
            if api_cmd is not None:
                xml_cmd = str(api_cmd)
                params["cmd"] = xml_cmd
            elif api_type == "op":
                xml_cmd = build_xml_from_command(command)
                params["cmd"] = xml_cmd

            if api_action:
                params["action"] = api_action
            if api_xpath:
                params["xpath"] = api_xpath
            if api_element is not None:
                params["element"] = api_element
            if isinstance(api_params, dict):
                for key, value in api_params.items():
                    if key is None or value is None:
                        continue
                    params[str(key)] = str(value)
            
            url = f"https://{self.endpoint}/api?{urllib.parse.urlencode(params)}"

            payload = xml_cmd.encode("utf-8") if xml_cmd else None
            effective_timeout = self._resolve_request_timeout(request_timeout)
            resp = requests.post(
                url,
                data=payload,
                headers=headers,
                verify=False,
                timeout=effective_timeout,
            )
            # need to raise for status.
            resp.raise_for_status()
            # print(resp.text)

            return xml_string_to_dict(resp.text)

        except Exception as e:
            print("Error:", e)

    def discover_panorama_managed_devices(
        self,
        include_templates: bool = True,
        include_raw: bool = False,
    ) -> dict:
        """
        Discover managed firewalls and policy topology from a Panorama controller.
        """
        system_info = self.execute("show system info")
        devices_payload = self.execute("show devices all")
        device_groups_payload = self.execute("show devicegroups")
        templates_payload = self.execute("show templates") if include_templates else None

        managed_devices = self._parse_panorama_managed_devices(devices_payload)
        groups_by_serial = self._parse_panorama_device_groups(device_groups_payload)
        templates_by_serial, template_stacks_by_serial = self._parse_panorama_template_assignments(templates_payload)

        for managed in managed_devices:
            serial = self._coalesce_payload_string(managed, "serial", "name", "deviceid", "device-id")
            managed["device_groups"] = groups_by_serial.get(serial, []) if serial else []
            managed["templates"] = templates_by_serial.get(serial, []) if serial else []
            managed["template_stacks"] = template_stacks_by_serial.get(serial, []) if serial else []

        controller_model = None
        controller_serial = None
        controller_hostname = None
        if isinstance(system_info, dict):
            entries = self._iter_entries_for_parent_keys(system_info, {"system"})
            if entries:
                candidate = entries[0]
                controller_model = self._coalesce_payload_string(candidate, "model")
                controller_serial = self._coalesce_payload_string(candidate, "serial")
                controller_hostname = self._coalesce_payload_string(candidate, "hostname", "host-name")
            if controller_model is None:
                controller_model = self._find_first_payload_string(system_info, "model")
            if controller_serial is None:
                controller_serial = self._find_first_payload_string(system_info, "serial")
            if controller_hostname is None:
                controller_hostname = self._find_first_payload_string(system_info, "hostname", "host-name")

        is_panorama = None
        if controller_model:
            is_panorama = "panorama" in str(controller_model).strip().lower()

        response = {
            "controller": {
                "endpoint": self.endpoint,
                "estate_id": getattr(self, "estate_id", self.endpoint),
                "hostname": controller_hostname,
                "serial": controller_serial,
                "model": controller_model,
                "is_panorama": is_panorama,
            },
            "managed_devices": managed_devices,
            "summary": {
                "managed_device_count": len(managed_devices),
                "connected_managed_count": len(
                    [
                        item
                        for item in managed_devices
                        if item.get("connected") is True
                    ]
                ),
                "device_group_count": len(
                    {
                        group
                        for item in managed_devices
                        for group in ensure_list(item.get("device_groups"))
                    }
                ),
                "template_count": len(
                    {
                        template
                        for item in managed_devices
                        for template in ensure_list(item.get("templates"))
                    }
                ),
                "template_stack_count": len(
                    {
                        stack
                        for item in managed_devices
                        for stack in ensure_list(item.get("template_stacks"))
                    }
                ),
            },
        }
        if include_raw:
            response["raw"] = {
                "system_info": system_info,
                "devices": devices_payload,
                "device_groups": device_groups_payload,
                "templates": templates_payload,
            }
        return response

    def _extract_url_category_members(self, node) -> list[str]:
        """
        Recursively collects URL category member values from known PAN-OS shapes.
        """
        members = []

        if isinstance(node, list):
            for item in node:
                members.extend(self._extract_url_category_members(item))
            return members

        if not isinstance(node, dict):
            if isinstance(node, (str, int, float)):
                return [str(node)]
            return []

        raw_members = node.get("member")
        if raw_members is not None:
            for item in ensure_list(raw_members):
                if isinstance(item, (str, int, float)):
                    members.append(str(item))

        for key in (
            "list",
            "type",
            "url",
            "url-list",
            "url_list",
            "urls",
            "urls-list",
            "regex",
            "pattern",
            "patterns",
            "site",
            "sites",
        ):
            if key in node:
                members.extend(self._extract_url_category_members(node.get(key)))

        return members

    def _extract_url_categories_from_payload(self, payload: dict | None, source: str) -> list[dict]:
        """
        Best-effort parser for `show url category` and config URL category responses.
        """
        out = []
        if not isinstance(payload, dict):
            return out

        def walk(node):
            if isinstance(node, dict):
                entry_block = node.get("entry")
                if entry_block is not None:
                    for entry in ensure_list(entry_block):
                        if not isinstance(entry, dict):
                            continue
                        name = entry.get("name")
                        if not name:
                            continue

                        cat_type = None
                        type_block = entry.get("type")
                        if isinstance(type_block, dict) and type_block:
                            cat_type = ",".join([str(k) for k in type_block.keys()])
                        elif isinstance(type_block, str):
                            cat_type = type_block

                        members = self._extract_url_category_members(entry)
                        # `name` is often also present in entry metadata; keep only value-like members.
                        members = [m for m in members if m != str(name)]

                        seen = set()
                        deduped_members = []
                        for member in members:
                            if member in seen:
                                continue
                            seen.add(member)
                            deduped_members.append(member)

                        out.append(
                            {
                                "name": str(name),
                                "type": cat_type,
                                "members": deduped_members,
                                "source": source,
                            }
                        )

                for value in node.values():
                    walk(value)

            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)

        # Deduplicate records by source+name while preserving first-seen ordering.
        merged = {}
        for record in out:
            key = (record.get("source"), record.get("name"))
            if key not in merged:
                merged[key] = {
                    "name": record.get("name"),
                    "type": record.get("type"),
                    "members": [],
                    "source": record.get("source"),
                }
            bucket = merged[key]
            if bucket.get("type") is None and record.get("type") is not None:
                bucket["type"] = record.get("type")

            existing = set(bucket.get("members", []))
            for member in ensure_list(record.get("members")):
                if member in existing:
                    continue
                existing.add(member)
                bucket["members"].append(member)

        return list(merged.values())

    def get_url_categories(self, include_config: bool = True, include_raw: bool = False):
        """
        Discovers URL categories from PAN-OS.

        Args:
            include_config (bool): Also query config XPath for custom URL categories.
            include_raw (bool): Include raw API responses for schema discovery/debugging.

        Returns:
            dict: {
                "categories": list[dict],
                "raw": dict (optional)
            }
        """
        categories = []
        raw = {}

        op_response = self.execute("show url category")
        categories.extend(self._extract_url_categories_from_payload(op_response, source="op"))
        if include_raw:
            raw["op"] = op_response

        config_warning = None
        if include_config:
            if not self.ensure_connected(fail_on_error=False):
                config_warning = f"config categories unavailable for {self.endpoint}: {self.connection_error}"
                if include_raw:
                    raw["config_error"] = self.connection_error
            else:
                vsys_entries = ensure_list(self.panos.config.devices.entry.vsys.entry)
                vsys_name = getattr(vsys_entries[0], "name", None) if vsys_entries else None
                if not vsys_name:
                    vsys_name = "vsys1"

                xpaths = [
                    (
                        f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/profiles/custom-url-category",
                        "config-vsys-custom-url-category",
                    ),
                    (
                        "/config/shared/profiles/custom-url-category",
                        "config-shared-custom-url-category",
                    ),
                ]

                for xpath, source in xpaths:
                    response = self.execute(api_type="config", api_action="get", api_xpath=xpath)
                    categories.extend(self._extract_url_categories_from_payload(response, source=source))
                    if include_raw:
                        raw[source] = response

        # Final dedupe by category name (case-insensitive), merging members/sources.
        merged = {}
        for record in categories:
            name = str(record.get("name", "")).strip()
            if not name:
                continue
            key = name.lower()
            if key not in merged:
                merged[key] = {
                    "name": name,
                    "type": record.get("type"),
                    "members": [],
                    "sources": [],
                }
            bucket = merged[key]
            if bucket.get("type") is None and record.get("type") is not None:
                bucket["type"] = record.get("type")

            source = record.get("source")
            if source and source not in bucket["sources"]:
                bucket["sources"].append(source)

            existing = set(bucket["members"])
            for member in ensure_list(record.get("members")):
                member = str(member)
                if member.strip().lower() in {"url list", "category match"}:
                    continue
                if member in existing:
                    continue
                existing.add(member)
                bucket["members"].append(member)

        result = {
            "categories": list(merged.values()),
        }
        if config_warning:
            result["warning"] = config_warning
        if include_raw:
            result["raw"] = raw
        return result

    def _extract_log_entries(self, response: dict | None) -> list[dict]:
        """
        Normalizes XML API log responses and returns log entries as a list.
        """
        if not isinstance(response, dict):
            return []

        result_block = response.get("response", {}).get("result")
        if not isinstance(result_block, dict):
            return []

        # PAN-OS may return logs under multiple shapes depending on endpoint/version:
        # result.logs.entry
        # result.log.logs.entry
        # result.job.logs.entry
        candidate_paths = []

        result_logs = result_block.get("logs")
        if isinstance(result_logs, dict):
            candidate_paths.append(result_logs)

        result_log = result_block.get("log")
        if isinstance(result_log, dict):
            nested_logs = result_log.get("logs")
            if isinstance(nested_logs, dict):
                candidate_paths.append(nested_logs)

        job_block = result_block.get("job")
        if isinstance(job_block, dict):
            job_logs = job_block.get("logs")
            if isinstance(job_logs, dict):
                candidate_paths.append(job_logs)

        for block in candidate_paths:
            entries = block.get("entry")
            if entries is None:
                continue
            return [entry for entry in ensure_list(entries) if isinstance(entry, dict)]

        return []

    def get_logs(
        self,
        query: str,
        log_type: str = "traffic",
        nlogs: int = 100,
        skip: int = 0,
        poll_interval: float = 1.0,
        timeout: int = 30,
    ) -> list[dict]:
        """
        Queries PAN-OS logs via XML API `type=log` and returns log entries.

        PAN-OS log queries are job-based. This helper starts the query and polls
        until entries are available or the job completes/timeout is reached.
        """
        if not query:
            raise ValueError("query must be a non-empty string")
        self._require_api_key()

        params = {
            "type": "log",
            "log-type": log_type,
            "query": query,
            "nlogs": nlogs,
            "skip": skip,
            "key": self.api_key,
        }
        url = f"https://{self.endpoint}/api?{urllib.parse.urlencode(params)}"

        try:
            resp = requests.get(url, verify=False)
            resp.raise_for_status()
            initial_response = xml_string_to_dict(resp.text)
        except Exception as e:
            print("Error:", e)
            return []

        entries = self._extract_log_entries(initial_response)
        if entries:
            return entries

        job_id = self.extract_job_id(initial_response)
        if not job_id:
            return []

        deadline = time.monotonic() + max(timeout, 0)
        while time.monotonic() <= deadline:
            poll_params = {
                "type": "log",
                "action": "get",
                "job-id": str(job_id),
                "key": self.api_key,
            }
            poll_url = f"https://{self.endpoint}/api?{urllib.parse.urlencode(poll_params)}"

            try:
                poll_resp = requests.get(poll_url, verify=False)
                poll_resp.raise_for_status()
                poll_response = xml_string_to_dict(poll_resp.text)
            except Exception as e:
                print("Error:", e)
                return []

            entries = self._extract_log_entries(poll_response)
            if entries:
                return entries

            status, _ = self._extract_job_status_result(poll_response)

            if str(status).upper() in {"FIN", "FINISHED", "DONE"}:
                return []

            time.sleep(max(0.1, poll_interval))

        return []

    def get_configuration(self, request_timeout: int | float = 60):
        """
        returns dictionary configuration, using tempfile for memory optimization. 
        """
        self._require_api_key()
        params = {
            "type": "export",
            "category": "configuration",
            "key": self.api_key,
        }
        url = f"https://{self.endpoint}/api/"

        # dump as xml first, convert to json then overwrite
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as out_file:
            # request configuration, stream output and write it to output file
            with requests.get(
                url,
                params=params,
                stream=True,
                verify=False,
                timeout=request_timeout,
            ) as r:
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=8192, decode_unicode=False):
                    if chunk:
                        out_file.write(chunk)
            temp_file_path = out_file.name

        # Convert the temporary XML file to a dictionary
        result = xml_file_to_dict(temp_file_path)
        # Clean up the temporary file
        os.unlink(temp_file_path)
        return result

    def export_configuration(self, output_filename=None, request_timeout: int | float = 60):
        self._require_api_key()
        params = {
            "type": "export",
            "category": "configuration",
            "key": self.api_key,
        }
        url = f"https://{self.endpoint}/api/"

        if output_filename is None:
            output_filename = f"{self.endpoint}_{get_current_time_string()}.json"

        # dump as xml first, convert to json then overwrite
        with open(output_filename, 'x') as out_file:
            # request configuration, stream output and write it to output file
            with requests.get(
                url,
                params=params,
                stream=True,
                verify=False,
                timeout=request_timeout,
            ) as r:
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=8192, decode_unicode=True):
                    if chunk:
                        out_file.write(chunk)

        data = xml_file_to_dict(output_filename)
        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


    '''
    Batch executes xml encoded Panorama commands
    '''
    def batch_execute(self, xml_commands: list[str], api_type: str = "op", api_action: str = None, api_xpath: str = None) -> list[str]:
        """
        Executes a batch of XML API commands (as strings) and returns their responses.

        Args:
            xml_commands (list[str]): List of XML-encoded command strings.
            api_type (str): API type parameter (default "op").
            api_action (str): API action parameter (optional).
            api_xpath (str): API xpath parameter (optional).

        Returns:
            list[str]: List of XML responses as strings.
        """
        headers = {
            "Content-Type": "application/xml"
        }
        responses = []
        for xml_cmd in xml_commands:

            params = {
                "type": api_type,
                "cmd": xml_cmd,
                "key": self.api_key
            }
            if api_action:
                params["action"] = api_action
            
            url = f"https://{self.endpoint}/api?{urllib.parse.urlencode(params)}"

            resp = requests.post(url, data=xml_cmd.encode('utf-8'), headers=headers, verify=False)
            # need to raise for status.
            resp.raise_for_status()
            responses.append(resp.text)
        return responses

    """============= PANOS Utility Functions =================="""

    def get_interfaces(self):
        return dataclass_to_dict(
            self.panos.config.devices.entry.network.interface
        )

    '''
    # attempt to resolve all routing tables unknown
    def get_routing_table(self):
        return dataclass_to_dict(
                self.panos.config.devices.entry.network
            )
    '''


    def resolve_ip_interface(self, ip: str):
        """
        Resolve an IP address to its source device/interface.
        
        Returns:
            dict with device, interface, cidr
            or None if not found

        """
        target_ip = ipaddress.ip_address(ip)

        layer3_devices = self.panos.config.devices.entry.network.interface.ethernet.entry
        ae_interfaces = self.panos.config.devices.entry.network.interface.aggregate_ethernet.entry
        layer3_devices = ensure_list(layer3_devices)
        ae_interfaces = ensure_list(ae_interfaces)

        cidr_tables = {}

        # standard L3 interfaces
        for device in layer3_devices:
            device_name = device.name

            # some interfaces do not have L3 configurations
            try:
                ip_entries = device.layer3
            except AttributeError:
                continue

            ip_entries = ensure_list(ip_entries)

            for ip_cidr in ip_entries:
                # print(vars(ip_cidr))
                # Skip DHClient interfaces
                try:
                    ip_entries = (
                        ip_cidr.ip.entry.name
                    )
                    ip_entries = ensure_list(ip_entries)

                    cidr_tables[device_name] = ip_entries
                except AttributeError:
                        continue 
                        
        # checking aggregate ethernet interface
        for device in ae_interfaces:
            device_name = device.name

            # some interfaces do not have L3 configurations
            try:
                ip_entries = device.layer3
            except AttributeError:
                continue

            ip_entries = ensure_list(ip_entries)

            for ip_cidr in ip_entries:
                # Skip DHClient interfaces / null L3 configs
                try:
                    ip_entries = (
                        ip_cidr.ip.entry.name
                    )
                    ip_entries = ensure_list(ip_entries)

                    cidr_tables[device_name] = ip_entries
                except AttributeError:
                    continue
        
        # checking tunnel interfaces etc...
        for interface, cidr in cidr_tables.items():
            for net in cidr:
                if contained_in(ip, net):
                    # print(interface, cidr)
                    # print(self.get_zone_by_interface(interface))
                    return {
                        "interface": interface,
                        "cidr": cidr,
                        "zone": self.get_zone_by_interface(interface)
                    }
        return None

    def get_zone_by_interface(self, interface):
        zones = ensure_list(self.get_zones())
        for zone in zones:
            zone_name = zone.name
            try:
                zone_members = ensure_list(zone.network.layer3.member)
                for member in zone_members:
                    if member == interface:
                        return zone_name

            except AttributeError:
                # L3 config is null, empty Zone
                continue

        return None

    def get_zone_by_ip_address(self, ip_address):
        # check interfaces by subnet, but also routing tables may be required.
        # 
        local_interface = self.resolve_ip_interface(ip_address)
        if local_interface is not None:
            return local_interface.get("zone")
        
        # the destination is not in the local config, must check routing table.

        routes = self.enumerate_routes()

        default_route_zone = 'default'
        for route, spec in routes.items():
            # check for default 0.0.0.0/0
            destination = spec.get('destination')
            route_zone = spec.get('destination_zone')

            if destination == '0.0.0.0/0':
                # skip default route for now, if no other routes contain destination
                default_route_zone = route_zone
            elif contained_in(ip_address, destination):
                return route_zone

        return default_route_zone
            
    
    def enumerate_routes(self):
        # local interface cache (more reliable for known configurations on host)
        virtual_routers = self.panos.config.devices.entry.network.virtual_router.entry
        virtual_routers = ensure_list(virtual_routers)

        route_dict = {}

        # check VRs first
        for router in virtual_routers:
            name = router.name
            # check static routes first
            routes = ensure_list(router.routing_table.ip.static_route.entry)
            # interfaces = ensure_list(router.interface.member)
            try:
                for route in routes:
                    route_dict[route.name] = {
                        "next_hop": route.nexthop.ip_address,
                        "interface": route.interface,
                        "destination": route.destination,
                        "destination_zone": self.get_zone_by_interface(route.interface)                        
                    }
            except AttributeError:
                # something odd about an entry....
                continue

        return route_dict

    def get_zones(self):
        return dataclass_to_dict(
            self.panos.config.devices.entry.vsys.entry.zone.entry
        )

    def get_dhcp(self):
        return ensure_list(
            dataclass_to_dict(
                self.panos.config.devices.entry.network.dhcp
            )
        )

    def get_rulebase(self):
        """
        Docstring for get_rulebase
        
        :param self: Description

        cmd: show rulebase security
        """
        vsys_entries = ensure_list(self.panos.config.devices.entry.vsys.entry)
        if not vsys_entries:
            raise ValueError("No vsys entries found in configuration")

        vsys_name = getattr(vsys_entries[0], "name", None) or "vsys1"
        xpath = f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/rulebase/security/rules"
        results = self.execute(api_type="config", api_action="get", api_xpath=xpath)
        if not isinstance(results, dict):
            return []

        result_block = results.get("response", {}).get("result")
        if not isinstance(result_block, dict):
            return []

        rules_block = result_block.get("rules")
        if not isinstance(rules_block, dict):
            return []

        entries = rules_block.get("entry")
        if entries is None:
            return []

        return ensure_list(entries)

    def _coerce_member_values(self, values, default=None) -> list[str]:
        if values is None:
            values = default if default is not None else []
        out = []
        for value in ensure_list(values):
            text = str(value).strip()
            if text:
                out.append(text)
        return out

    def get_policy_defaults(self) -> dict:
        """
        Returns effective policy defaults for this instance.
        """
        if not isinstance(self.policy_defaults, dict):
            return {}
        return deepcopy(self.policy_defaults)

    def _build_member_container_xml(self, parent: ET.Element, tag_name: str, members: list[str]) -> None:
        block = ET.SubElement(parent, tag_name)
        for member in members:
            ET.SubElement(block, "member").text = str(member)

    def _build_security_rule_entry_xml(
        self,
        rule_name: str,
        from_zones: list[str],
        to_zones: list[str],
        sources: list[str],
        destinations: list[str],
        applications: list[str],
        services: list[str],
        action: str,
        description: str | None = None,
        disabled: bool = False,
        log_start: bool | None = None,
        log_end: bool | None = None,
        tags: list[str] | None = None,
        profile_setting_group: str | None = None,
        log_setting: str | None = None,
    ) -> str:
        """
        Build PAN-OS security rule `<entry>` XML payload.
        """
        entry = ET.Element("entry", {"name": rule_name})
        self._build_member_container_xml(entry, "from", from_zones)
        self._build_member_container_xml(entry, "to", to_zones)
        self._build_member_container_xml(entry, "source", sources)
        self._build_member_container_xml(entry, "destination", destinations)
        self._build_member_container_xml(entry, "application", applications)
        self._build_member_container_xml(entry, "service", services)

        ET.SubElement(entry, "action").text = action

        if description is not None:
            ET.SubElement(entry, "description").text = str(description)

        ET.SubElement(entry, "disabled").text = "yes" if disabled else "no"
        if log_start is not None:
            ET.SubElement(entry, "log-start").text = "yes" if bool(log_start) else "no"
        if log_end is not None:
            ET.SubElement(entry, "log-end").text = "yes" if bool(log_end) else "no"
        if tags:
            self._build_member_container_xml(entry, "tag", tags)
        if profile_setting_group:
            profile_setting = ET.SubElement(entry, "profile-setting")
            group = ET.SubElement(profile_setting, "group")
            ET.SubElement(group, "member").text = str(profile_setting_group)
        if log_setting:
            ET.SubElement(entry, "log-setting").text = str(log_setting)

        return ET.tostring(entry, encoding="unicode", method="xml")

    def create_security_rule(
        self,
        rule_name: str,
        from_zones=None,
        to_zones=None,
        sources=None,
        destinations=None,
        applications=None,
        services=None,
        action: str | None = None,
        description: str | None = None,
        disabled: bool | None = None,
        log_start: bool | None = None,
        log_end: bool | None = None,
        tags=None,
        profile_setting_group: str | None = None,
        log_setting: str | None = None,
        vsys_name: str | None = None,
        position: str | None = None,
        reference_rule: str | None = None,
        auto_commit: bool | None = None,
        commit_wait_for_job: bool | None = None,
        commit_timeout: int | float | None = None,
        commit_poll_interval: int | float | None = None,
    ) -> dict:
        """
        Create a security rule via PAN-OS XML API config calls.

        Args:
            rule_name: Security rule entry name.
            from_zones/to_zones: Zone member(s).
            sources/destinations: Address selectors. Defaults to `any`.
            applications: App-ID member(s). Defaults to `any`.
            services: Service member(s). Defaults to `application-default`.
            action: Rule action (allow, deny, drop, reset-client, reset-server, reset-both).
            position: Optional move target (`before` or `after`) after creation.
            reference_rule: Required when `position` is used.
        """
        normalized_rule_name = str(rule_name).strip()
        if not normalized_rule_name:
            raise ValueError("rule_name must be a non-empty string")

        policy_defaults = self.get_policy_defaults()
        rule_defaults = {}
        placement_defaults = {}
        commit_defaults = {}
        if isinstance(policy_defaults.get("rule_create"), dict):
            rule_defaults = policy_defaults.get("rule_create")
        elif isinstance(policy_defaults, dict):
            rule_defaults = {}
        if isinstance(policy_defaults.get("placement"), dict):
            placement_defaults = policy_defaults.get("placement")
        if isinstance(policy_defaults.get("commit"), dict):
            commit_defaults = policy_defaults.get("commit")

        if action is None:
            action = rule_defaults.get("action", "allow")
        normalized_action = str(action).strip().lower()
        valid_actions = {"allow", "deny", "drop", "reset-client", "reset-server", "reset-both"}
        if normalized_action not in valid_actions:
            raise ValueError(f"unsupported action `{action}`; expected one of {sorted(valid_actions)}")

        normalized_from = self._coerce_member_values(from_zones, default=rule_defaults.get("from_zones", ["any"]))
        normalized_to = self._coerce_member_values(to_zones, default=rule_defaults.get("to_zones", ["any"]))
        if not normalized_from:
            raise ValueError("from_zones must include at least one zone")
        if not normalized_to:
            raise ValueError("to_zones must include at least one zone")

        normalized_sources = self._coerce_member_values(
            sources,
            default=rule_defaults.get("sources", ["any"]),
        )
        normalized_destinations = self._coerce_member_values(
            destinations,
            default=rule_defaults.get("destinations", ["any"]),
        )
        normalized_apps = self._coerce_member_values(
            applications,
            default=rule_defaults.get("applications", ["any"]),
        )
        normalized_services = self._coerce_member_values(
            services,
            default=rule_defaults.get("services", ["application-default"]),
        )

        if description is None:
            description = rule_defaults.get("description")
            description_prefix = rule_defaults.get("description_prefix")
            if description is None and isinstance(description_prefix, str) and description_prefix.strip():
                description = f"{description_prefix.strip()} {normalized_rule_name}"

        if disabled is None:
            disabled = bool(rule_defaults.get("disabled", False))

        if log_start is None and "log_start" in rule_defaults:
            log_start = bool(rule_defaults.get("log_start"))
        if log_end is None and "log_end" in rule_defaults:
            log_end = bool(rule_defaults.get("log_end"))

        resolved_tags = self._coerce_member_values(tags, default=rule_defaults.get("tags"))
        if profile_setting_group is None:
            profile_setting_group = rule_defaults.get("profile_setting_group")
        if log_setting is None:
            log_setting = rule_defaults.get("log_setting")

        if vsys_name is None:
            vsys_name = rule_defaults.get("vsys_name")
        if vsys_name is None:
            vsys_name = self._default_vsys_name()
        vsys_name = str(vsys_name).strip() or "vsys1"

        if position is None:
            position = placement_defaults.get("position")
        if reference_rule is None:
            reference_rule = placement_defaults.get("reference_rule")

        rules_xpath = f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/rulebase/security/rules"
        entry_xml = self._build_security_rule_entry_xml(
            rule_name=normalized_rule_name,
            from_zones=normalized_from,
            to_zones=normalized_to,
            sources=normalized_sources,
            destinations=normalized_destinations,
            applications=normalized_apps,
            services=normalized_services,
            action=normalized_action,
            description=description,
            disabled=bool(disabled),
            log_start=log_start,
            log_end=log_end,
            tags=resolved_tags,
            profile_setting_group=profile_setting_group,
            log_setting=log_setting,
        )

        create_response = self.execute(
            api_type="config",
            api_action="set",
            api_xpath=rules_xpath,
            api_element=entry_xml,
        )

        result = {
            "created": bool(create_response),
            "rule_name": normalized_rule_name,
            "vsys": vsys_name,
            "xpath": rules_xpath,
            "request": {
                "action": normalized_action,
                "from": normalized_from,
                "to": normalized_to,
                "source": normalized_sources,
                "destination": normalized_destinations,
                "application": normalized_apps,
                "service": normalized_services,
                "tags": resolved_tags,
                "profile_setting_group": profile_setting_group,
                "log_setting": log_setting,
            },
            "create_status": self._response_status(create_response),
            "create_code": self._response_code(create_response),
            "create_response": create_response,
            "moved": False,
            "move_response": None,
            "committed": False,
            "commit_result": None,
        }

        if position is None:
            pass
        else:
            normalized_position = str(position).strip().lower()
            if normalized_position not in {"before", "after"}:
                raise ValueError("position must be either `before` or `after` when provided")
            if not reference_rule or not str(reference_rule).strip():
                raise ValueError("reference_rule is required when position is provided")

            entry_xpath = f"{rules_xpath}/entry[@name='{normalized_rule_name}']"
            move_response = self.execute(
                api_type="config",
                api_action="move",
                api_xpath=entry_xpath,
                api_params={
                    "where": normalized_position,
                    "dst": str(reference_rule).strip(),
                },
            )
            result["moved"] = bool(move_response)
            result["move_response"] = move_response

        if auto_commit is None:
            auto_commit = bool(commit_defaults.get("enabled", False))
        if auto_commit:
            if commit_wait_for_job is None:
                commit_wait_for_job = bool(commit_defaults.get("wait_for_job", True))
            if commit_timeout is None:
                commit_timeout = commit_defaults.get("timeout", 300)
            if commit_poll_interval is None:
                commit_poll_interval = commit_defaults.get("poll_interval", 2)

            commit_result = self.commit(
                wait_for_job=bool(commit_wait_for_job),
                timeout=float(commit_timeout),
                poll_interval=float(commit_poll_interval),
            )
            result["committed"] = bool(commit_result.get("success"))
            result["commit_result"] = commit_result

        return result

    def _response_status(self, response: dict | None) -> str | None:
        if not isinstance(response, dict):
            return None
        status = response.get("response", {}).get("status")
        if status is None:
            return None
        return str(status)

    def _response_code(self, response: dict | None) -> str | None:
        if not isinstance(response, dict):
            return None
        code = response.get("response", {}).get("code")
        if code is None:
            return None
        return str(code)

    def _response_result(self, response: dict | None):
        if not isinstance(response, dict):
            return None
        result = response.get("response", {}).get("result")
        return result if isinstance(result, dict) else None

    def _payload_contains_named_entry(self, node, rule_name: str) -> bool:
        if isinstance(node, list):
            return any(self._payload_contains_named_entry(item, rule_name) for item in node)
        if not isinstance(node, dict):
            return False

        node_name = node.get("name")
        if isinstance(node_name, str) and node_name == rule_name:
            return True

        for key, value in node.items():
            if key == "name":
                continue
            if self._payload_contains_named_entry(value, rule_name):
                return True
        return False

    def _security_rule_xpath(self, vsys_name: str, rule_name: str | None = None) -> str:
        base_xpath = f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/rulebase/security/rules"
        if rule_name is None:
            return base_xpath
        return f"{base_xpath}/entry[@name='{rule_name}']"

    def _security_rule_exists(self, rule_name: str, vsys_name: str) -> tuple[bool, dict | None]:
        check_response = self.execute(
            api_type="config",
            api_action="get",
            api_xpath=self._security_rule_xpath(vsys_name, rule_name),
        )
        if not isinstance(check_response, dict):
            return False, check_response

        if self._response_status(check_response) != "success":
            return False, check_response

        result_block = self._response_result(check_response)
        if not isinstance(result_block, dict):
            return False, check_response

        return self._payload_contains_named_entry(result_block, rule_name), check_response

    def delete_security_rule(
        self,
        rule_name: str,
        vsys_name: str | None = None,
        ignore_missing: bool = False,
    ) -> dict:
        """
        Delete a security rule by name from rulebase/security/rules.
        """
        normalized_rule_name = str(rule_name).strip()
        if not normalized_rule_name:
            raise ValueError("rule_name must be a non-empty string")

        if vsys_name is None:
            vsys_name = self._default_vsys_name()
        normalized_vsys = str(vsys_name).strip() or "vsys1"

        exists_before, check_before_response = self._security_rule_exists(
            rule_name=normalized_rule_name,
            vsys_name=normalized_vsys,
        )

        if not exists_before:
            if not ignore_missing:
                raise ValueError(
                    f"security rule `{normalized_rule_name}` does not exist in vsys `{normalized_vsys}`"
                )
            return {
                "deleted": False,
                "rule_name": normalized_rule_name,
                "vsys": normalized_vsys,
                "exists_before": False,
                "exists_after": False,
                "delete_response": None,
                "check_before_response": check_before_response,
                "check_after_response": check_before_response,
                "reason": "rule_not_found",
            }

        delete_response = self.execute(
            api_type="config",
            api_action="delete",
            api_xpath=self._security_rule_xpath(normalized_vsys, normalized_rule_name),
        )

        exists_after, check_after_response = self._security_rule_exists(
            rule_name=normalized_rule_name,
            vsys_name=normalized_vsys,
        )

        return {
            "deleted": bool(delete_response) and (not exists_after),
            "rule_name": normalized_rule_name,
            "vsys": normalized_vsys,
            "exists_before": exists_before,
            "exists_after": exists_after,
            "delete_status": self._response_status(delete_response),
            "delete_code": self._response_code(delete_response),
            "delete_response": delete_response,
            "check_before_response": check_before_response,
            "check_after_response": check_after_response,
            "reason": None if (delete_response and not exists_after) else "delete_not_confirmed",
        }

    @staticmethod
    def _scalar_text(value: Any) -> str | None:
        if not isinstance(value, (str, int, float)):
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _walk_payload_nodes(payload: Any):
        stack = [payload]
        while stack:
            node = stack.pop()
            yield node
            if isinstance(node, dict):
                for value in reversed(list(node.values())):
                    stack.append(value)
            elif isinstance(node, list):
                for item in reversed(node):
                    stack.append(item)

    def _extract_job_id(self, response: dict | None) -> str | None:
        result_block = self._response_result(response)
        if not isinstance(result_block, dict):
            return None

        for node in self._walk_payload_nodes(result_block):
            if not isinstance(node, dict):
                continue

            for key in ("job", "jobid", "job-id"):
                if key not in node:
                    continue

                value = node.get(key)
                if key == "job" and isinstance(value, dict):
                    for candidate_key in ("id", "jobid", "job-id", "_text", "value"):
                        job_id = self._scalar_text(value.get(candidate_key))
                        if job_id:
                            return job_id

                job_id = self._scalar_text(value)
                if job_id:
                    return job_id

        return None

    def extract_job_id(self, response: dict | None) -> str | None:
        """
        Return the PAN-OS job ID from a command response when one is present.
        """
        return self._extract_job_id(response)

    def _extract_job_status_result(self, response: dict | None) -> tuple[str | None, str | None]:
        result_block = self._response_result(response)
        if not isinstance(result_block, dict):
            return None, None

        for node in self._walk_payload_nodes(result_block):
            if not isinstance(node, dict):
                continue

            job_block = node.get("job")
            if isinstance(job_block, dict):
                job_status = self._scalar_text(job_block.get("status"))
                if job_status:
                    return job_status, self._scalar_text(job_block.get("result"))

            status = self._scalar_text(node.get("status"))
            if status:
                return status, self._scalar_text(node.get("result"))

        return None, None

    def commit(
        self,
        wait_for_job: bool = True,
        timeout: int | float = 300,
        poll_interval: int | float = 2,
        request_timeout: int | float | None = None,
    ) -> dict:
        """
        Submit a candidate-config commit and optionally wait for job completion.
        """
        submit_response = self.execute(
            api_type="commit",
            api_cmd="<commit></commit>",
            request_timeout=request_timeout,
        )
        submit_status = self._response_status(submit_response)
        submit_code = self._response_code(submit_response)
        job_id = self.extract_job_id(submit_response)

        result = {
            "submitted": bool(submit_response),
            "submit_status": submit_status,
            "submit_code": submit_code,
            "job_id": job_id,
            "waited": bool(wait_for_job and job_id),
            "job_complete": False,
            "job_status": None,
            "job_result": None,
            "success": False,
            "submit_response": submit_response,
            "job_response": None,
        }

        if not wait_for_job or not job_id:
            result["success"] = submit_status == "success"
            return result

        deadline = time.monotonic() + max(0, float(timeout))
        final_states = {"FIN", "FINISHED", "DONE", "FAIL", "FAILED"}
        last_job_response = None

        while time.monotonic() <= deadline:
            job_response = self.execute(
                api_type="op",
                api_cmd=f"<show><jobs><id>{job_id}</id></jobs></show>",
                request_timeout=request_timeout,
            )
            last_job_response = job_response
            job_status, job_result = self._extract_job_status_result(job_response)
            result["job_status"] = job_status
            result["job_result"] = job_result

            normalized_status = str(job_status).strip().upper() if job_status is not None else ""
            if normalized_status in final_states:
                result["job_complete"] = True
                break

            time.sleep(max(0.1, float(poll_interval)))

        result["job_response"] = last_job_response
        normalized_status = str(result["job_status"]).strip().upper() if result["job_status"] is not None else ""
        normalized_result = str(result["job_result"]).strip().upper() if result["job_result"] is not None else ""
        result["success"] = (
            submit_status == "success"
            and result["job_complete"]
            and normalized_status in {"FIN", "FINISHED", "DONE"}
            and normalized_result not in {"FAIL", "FAILED"}
        )
        return result

    def get_addresses(self):
        """Returns addresses on PanOS Configuration"""
        vsys_entries = ensure_list(self.panos.config.devices.entry.vsys.entry)
        if not vsys_entries:
            raise ValueError("No vsys entries found in configuration")

        vsys_name = getattr(vsys_entries[0], "name", None) or "vsys1"
        xpath = f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/address"
        results = self.execute(api_type="config", api_action="get", api_xpath=xpath)
        if not isinstance(results, dict):
            return []

        result_block = results.get("response", {}).get("result")
        if not isinstance(result_block, dict):
            return []

        address_block = result_block.get("address")
        if not isinstance(address_block, dict):
            return []

        entries = address_block.get("entry")
        if entries is None:
            return []

        return ensure_list(entries)

    def get_address_groups(self):
        """Returns address groups on PanOS Configuration"""
        vsys_entries = ensure_list(self.panos.config.devices.entry.vsys.entry)
        if not vsys_entries:
            raise ValueError("No vsys entries found in configuration")

        vsys_name = getattr(vsys_entries[0], "name", None) or "vsys1"
        xpath = f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/address-group"
        results = self.execute(api_type="config", api_action="get", api_xpath=xpath)
        if not isinstance(results, dict):
            return []

        result_block = results.get("response", {}).get("result")
        if not isinstance(result_block, dict):
            return []

        group_block = result_block.get("address-group")
        if not isinstance(group_block, dict):
            return []

        entries = group_block.get("entry")
        if entries is None:
            return []

        return ensure_list(entries)

    def _default_vsys_name(self) -> str:
        """
        Best-effort default vsys resolver for config XPath helpers.
        """
        if not self.ensure_connected(fail_on_error=False):
            return "vsys1"

        try:
            vsys_entries = ensure_list(self.panos.config.devices.entry.vsys.entry)
        except AttributeError:
            return "vsys1"

        if not vsys_entries:
            return "vsys1"

        return getattr(vsys_entries[0], "name", None) or "vsys1"

    def _extract_named_entries(self, payload: dict | None, container_keys: tuple[str, ...]) -> list[dict]:
        """
        Recursively extract named `entry` dictionaries under one or more container keys.
        """
        out = []
        if not isinstance(payload, dict):
            return out

        def walk(node):
            if isinstance(node, dict):
                for key in container_keys:
                    container = node.get(key)
                    if not isinstance(container, dict):
                        continue
                    entries = container.get("entry")
                    if entries is None:
                        continue
                    for entry in ensure_list(entries):
                        if isinstance(entry, dict) and entry.get("name"):
                            out.append(entry)
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)

        deduped = []
        seen = set()
        for entry in out:
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(entry)
        return deduped

    def _extract_service_protocols(self, service_entry: dict) -> dict:
        """
        Parse PAN-OS service object protocol/port fields into normalized lists.
        """
        out = {}
        if not isinstance(service_entry, dict):
            return out

        protocol_block = service_entry.get("protocol")
        if not isinstance(protocol_block, dict):
            return out

        def parse_port_spec(value) -> list[str]:
            members = []
            if value is None:
                return members
            if isinstance(value, dict):
                raw_members = value.get("member")
                if raw_members is not None:
                    for member in ensure_list(raw_members):
                        if member is not None:
                            members.append(str(member).strip())
                text = value.get("_text")
                if isinstance(text, str) and text.strip():
                    members.append(text.strip())
            elif isinstance(value, list):
                for item in value:
                    if item is not None:
                        members.append(str(item).strip())
            elif isinstance(value, (str, int, float)):
                members.extend([part.strip() for part in str(value).split(",") if part.strip()])
            return list(dict.fromkeys([x for x in members if x]))

        for proto in ("tcp", "udp", "sctp"):
            proto_block = protocol_block.get(proto)
            if not isinstance(proto_block, dict):
                continue
            destination_ports = parse_port_spec(proto_block.get("port"))
            source_ports = parse_port_spec(proto_block.get("source-port"))
            if destination_ports or source_ports:
                out[proto] = {
                    "destination_ports": destination_ports,
                    "source_ports": source_ports,
                }

        return out

    def _extract_application_default_ports(self, app_entry: dict) -> dict:
        """
        Parse PAN-OS application-default protocol/port hints when available.
        """
        defaults = {}
        if not isinstance(app_entry, dict):
            return defaults

        default_block = app_entry.get("default")
        if not isinstance(default_block, dict):
            return defaults

        def parse_port_spec(value) -> list[str]:
            members = []
            if value is None:
                return members
            if isinstance(value, dict):
                raw_members = value.get("member")
                if raw_members is not None:
                    for member in ensure_list(raw_members):
                        if member is not None:
                            members.append(str(member).strip())
                text = value.get("_text")
                if isinstance(text, str) and text.strip():
                    members.append(text.strip())
            elif isinstance(value, list):
                for item in value:
                    if item is not None:
                        members.append(str(item).strip())
            elif isinstance(value, (str, int, float)):
                members.extend([part.strip() for part in str(value).split(",") if part.strip()])
            return list(dict.fromkeys([x for x in members if x]))

        for proto in ("tcp", "udp"):
            proto_block = default_block.get(proto)
            if not isinstance(proto_block, dict):
                continue
            ports = parse_port_spec(proto_block.get("port"))
            if ports:
                defaults[proto] = ports

        # Some PAN-OS payloads return mixed tokens in default.port (e.g., tcp/443,udp/53).
        mixed_port_field = default_block.get("port")
        for token in parse_port_spec(mixed_port_field):
            token_l = token.lower()
            match = re.match(r"^(tcp|udp)\s*/\s*(.+)$", token_l)
            if not match:
                continue
            proto = match.group(1)
            port_spec = match.group(2).strip()
            defaults.setdefault(proto, [])
            if port_spec and port_spec not in defaults[proto]:
                defaults[proto].append(port_spec)

        return defaults

    def get_services(self, include_shared: bool = True) -> list[dict]:
        """
        Return service objects from vsys (and optionally shared) configuration.
        """
        vsys_name = self._default_vsys_name()
        xpaths = [
            (
                f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/service",
                "vsys",
            ),
        ]
        if include_shared:
            xpaths.append(("/config/shared/service", "shared"))

        collected = []
        for xpath, scope in xpaths:
            response = self.execute(api_type="config", api_action="get", api_xpath=xpath)
            for entry in self._extract_named_entries(response, ("service",)):
                enriched = dict(entry)
                enriched["_scope"] = scope
                enriched["_protocols"] = self._extract_service_protocols(entry)
                collected.append(enriched)

        deduped = []
        seen = set()
        for entry in collected:
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(entry)
        return deduped

    def get_service_groups(self, include_shared: bool = True) -> list[dict]:
        """
        Return service-group objects from vsys (and optionally shared) configuration.
        """
        vsys_name = self._default_vsys_name()
        xpaths = [
            (
                f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/service-group",
                "vsys",
            ),
        ]
        if include_shared:
            xpaths.append(("/config/shared/service-group", "shared"))

        collected = []
        for xpath, scope in xpaths:
            response = self.execute(api_type="config", api_action="get", api_xpath=xpath)
            for entry in self._extract_named_entries(response, ("service-group",)):
                enriched = dict(entry)
                enriched["_scope"] = scope
                collected.append(enriched)

        deduped = []
        seen = set()
        for entry in collected:
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(entry)
        return deduped

    def get_applications(
        self,
        include_shared: bool = True,
        include_predefined: bool = True,
    ) -> list[dict]:
        """
        Return application objects for App-ID matching/validation.
        """
        vsys_name = self._default_vsys_name()
        xpaths = [
            (
                f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/application",
                "vsys",
            ),
        ]
        if include_shared:
            xpaths.append(("/config/shared/application", "shared"))
        if include_predefined:
            xpaths.append(("/config/predefined/application", "predefined"))

        collected = []
        for xpath, scope in xpaths:
            response = self.execute(api_type="config", api_action="get", api_xpath=xpath)
            for entry in self._extract_named_entries(response, ("application",)):
                enriched = dict(entry)
                enriched["_scope"] = scope
                enriched["_defaults"] = self._extract_application_default_ports(entry)
                collected.append(enriched)

        deduped = []
        seen = set()
        for entry in collected:
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(entry)
        return deduped

    def get_application_groups(
        self,
        include_shared: bool = True,
        include_predefined: bool = False,
    ) -> list[dict]:
        """
        Return application-group objects for App-ID group-aware matching.
        """
        vsys_name = self._default_vsys_name()
        xpaths = [
            (
                f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/application-group",
                "vsys",
            ),
        ]
        if include_shared:
            xpaths.append(("/config/shared/application-group", "shared"))
        if include_predefined:
            xpaths.append(("/config/predefined/application-group", "predefined"))

        collected = []
        for xpath, scope in xpaths:
            response = self.execute(api_type="config", api_action="get", api_xpath=xpath)
            for entry in self._extract_named_entries(response, ("application-group",)):
                enriched = dict(entry)
                enriched["_scope"] = scope
                collected.append(enriched)

        deduped = []
        seen = set()
        for entry in collected:
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(entry)
        return deduped

    def merge_rulebase_service_objects(self, rulebase=None, services=None, service_groups=None):
        """
        Resolves rulebase service selectors into service/service-group object details.
        """
        def dedupe(values):
            seen = set()
            ordered = []
            for value in values:
                try:
                    marker = ("hashable", value)
                    hash(marker)
                except TypeError:
                    marker = ("json", json.dumps(value, sort_keys=True, default=str))
                if marker in seen:
                    continue
                seen.add(marker)
                ordered.append(value)
            return ordered

        def member_list(block):
            if not isinstance(block, dict):
                return []
            members = block.get("member")
            if members is None:
                return []
            normalized = []
            for member in ensure_list(members):
                if isinstance(member, dict):
                    text_value = member.get("_text")
                    if text_value is None:
                        text_value = member.get("name")
                    if text_value is None:
                        text_value = json.dumps(member, sort_keys=True, default=str)
                    member = text_value
                text = str(member).strip()
                if text:
                    normalized.append(text)
            return normalized

        def protocol_port_hints(protocols: dict) -> list[str]:
            hints = []
            if not isinstance(protocols, dict):
                return hints
            for proto, spec in protocols.items():
                if not isinstance(spec, dict):
                    continue
                for port_spec in ensure_list(spec.get("destination_ports")):
                    hints.append(f"{proto}/{port_spec}")
            return dedupe(hints)

        rules = ensure_list(rulebase if rulebase is not None else self.get_rulebase())
        services = ensure_list(services if services is not None else self.get_services())
        service_groups = ensure_list(service_groups if service_groups is not None else self.get_service_groups())

        service_index = {
            obj.get("name"): obj for obj in services
            if isinstance(obj, dict) and obj.get("name")
        }
        group_index = {
            obj.get("name"): obj for obj in service_groups
            if isinstance(obj, dict) and obj.get("name")
        }

        def resolve_name(name, recursion_guard=None):
            if recursion_guard is None:
                recursion_guard = set()

            result = {
                "objects": [],
                "groups": [],
                "protocols": {},
                "port_hints": [],
                "unresolved": [],
            }

            if name in ("any", None):
                result["objects"] = [name]
                result["port_hints"] = ["any"]
                return result

            if name == "application-default":
                result["objects"] = [name]
                result["port_hints"] = ["application-default"]
                return result

            if name in recursion_guard:
                result["unresolved"] = [name]
                return result

            if name in service_index:
                service_obj = service_index[name]
                protocols = service_obj.get("_protocols")
                if not isinstance(protocols, dict):
                    protocols = self._extract_service_protocols(service_obj)
                result["objects"] = [name]
                result["protocols"] = protocols
                result["port_hints"] = protocol_port_hints(protocols)
                return result

            if name in group_index:
                recursion_guard = set(recursion_guard)
                recursion_guard.add(name)

                group_obj = group_index[name]
                members = member_list(group_obj.get("members"))
                nested_results = [resolve_name(member, recursion_guard) for member in members]

                result["groups"] = [name]
                result["objects"] = [name]

                for nested in nested_results:
                    result["objects"].extend(nested["objects"])
                    result["groups"].extend(nested["groups"])
                    result["port_hints"].extend(nested["port_hints"])
                    result["unresolved"].extend(nested["unresolved"])

                    for proto, spec in nested.get("protocols", {}).items():
                        existing = result["protocols"].setdefault(
                            proto,
                            {
                                "destination_ports": [],
                                "source_ports": [],
                            },
                        )
                        existing["destination_ports"].extend(ensure_list(spec.get("destination_ports")))
                        existing["source_ports"].extend(ensure_list(spec.get("source_ports")))
                        existing["destination_ports"] = dedupe(existing["destination_ports"])
                        existing["source_ports"] = dedupe(existing["source_ports"])

                result["objects"] = dedupe(result["objects"])
                result["groups"] = dedupe(result["groups"])
                result["port_hints"] = dedupe(result["port_hints"])
                result["unresolved"] = dedupe(result["unresolved"])
                return result

            result["objects"] = [name]
            result["unresolved"] = [name]
            return result

        def resolve_members(members):
            aggregate = {
                "input_members": dedupe(members),
                "objects": [],
                "groups": [],
                "protocols": {},
                "port_hints": [],
                "unresolved": [],
            }
            for member in members:
                resolved = resolve_name(member)
                aggregate["objects"].extend(resolved["objects"])
                aggregate["groups"].extend(resolved["groups"])
                aggregate["port_hints"].extend(resolved["port_hints"])
                aggregate["unresolved"].extend(resolved["unresolved"])

                for proto, spec in resolved.get("protocols", {}).items():
                    existing = aggregate["protocols"].setdefault(
                        proto,
                        {
                            "destination_ports": [],
                            "source_ports": [],
                        },
                    )
                    existing["destination_ports"].extend(ensure_list(spec.get("destination_ports")))
                    existing["source_ports"].extend(ensure_list(spec.get("source_ports")))
                    existing["destination_ports"] = dedupe(existing["destination_ports"])
                    existing["source_ports"] = dedupe(existing["source_ports"])

            aggregate["objects"] = dedupe(aggregate["objects"])
            aggregate["groups"] = dedupe(aggregate["groups"])
            aggregate["port_hints"] = dedupe(aggregate["port_hints"])
            aggregate["unresolved"] = dedupe(aggregate["unresolved"])
            return aggregate

        merged_rules = []
        unresolved_total = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue

            service_members = member_list(rule.get("service"))
            service_resolved = resolve_members(service_members)
            unresolved_total.extend(service_resolved["unresolved"])

            enriched_rule = dict(rule)
            enriched_rule["service_resolved"] = service_resolved
            merged_rules.append(enriched_rule)

        return {
            "rules": merged_rules,
            "summary": {
                "rule_count": len(merged_rules),
                "service_count": len(service_index),
                "service_group_count": len(group_index),
                "unresolved_objects": dedupe(unresolved_total),
            },
        }

    def merge_rulebase_address_objects(self, rulebase=None, addresses=None, address_groups=None):
        """
        Resolves rulebase source/destination object names into object values and IPv4 values.
        """
        def dedupe(values):
            seen = set()
            ordered = []
            for value in values:
                try:
                    marker = ("hashable", value)
                    hash(marker)
                except TypeError:
                    marker = ("json", json.dumps(value, sort_keys=True, default=str))
                if marker in seen:
                    continue
                seen.add(marker)
                ordered.append(value)
            return ordered

        def member_list(block):
            if not isinstance(block, dict):
                return []
            members = block.get("member")
            if members is None:
                return []
            normalized = []
            for member in ensure_list(members):
                if isinstance(member, dict):
                    text_value = member.get("_text")
                    if text_value is None:
                        text_value = member.get("name")
                    if text_value is None:
                        text_value = json.dumps(member, sort_keys=True, default=str)
                    member = text_value
                text = str(member).strip()
                if text:
                    normalized.append(text)
            return normalized

        def object_values(addr_obj):
            values = []
            for key in ("ip-netmask", "ip-range", "fqdn"):
                value = addr_obj.get(key)
                if value:
                    values.append(value)
            return values

        def ipv4_only(values):
            out = []
            for value in values:
                candidate = str(value).split("/", 1)[0].split("-", 1)[0]
                try:
                    ip = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if ip.version == 4:
                    out.append(value)
            return out

        rules = ensure_list(rulebase if rulebase is not None else self.get_rulebase())
        addresses = ensure_list(addresses if addresses is not None else self.get_addresses())
        address_groups = ensure_list(address_groups if address_groups is not None else self.get_address_groups())

        address_index = {
            obj.get("name"): obj for obj in addresses
            if isinstance(obj, dict) and obj.get("name")
        }
        group_index = {
            obj.get("name"): obj for obj in address_groups
            if isinstance(obj, dict) and obj.get("name")
        }

        def resolve_name(name, recursion_guard=None):
            if recursion_guard is None:
                recursion_guard = set()

            name_token = name
            if isinstance(name_token, dict):
                extracted = name_token.get("_text")
                if extracted is None:
                    extracted = name_token.get("name")
                if extracted is None:
                    extracted = json.dumps(name_token, sort_keys=True, default=str)
                name_token = extracted
            if name_token is not None:
                name_token = str(name_token).strip()
                if not name_token:
                    name_token = None

            result = {
                "objects": [],
                "groups": [],
                "values": [],
                "ipv4_values": [],
                "unresolved": [],
            }

            if name_token in ("any", None):
                result["objects"] = [name_token]
                result["values"] = [name_token, "0.0.0.0/0"]
                result["ipv4_values"] = ["0.0.0.0/0"]
                return result

            # Direct literal destination/source members are valid PAN-OS selectors.
            try:
                literal = name_token
                if literal and "/" in literal:
                    network = ipaddress.ip_network(literal, strict=False)
                    if network.version == 4:
                        result["objects"] = [literal]
                        result["values"] = [literal]
                        result["ipv4_values"] = [literal]
                        return result
                elif literal and "-" in literal:
                    start_raw, end_raw = literal.split("-", 1)
                    start_ip = ipaddress.ip_address(start_raw.strip())
                    end_ip = ipaddress.ip_address(end_raw.strip())
                    if start_ip.version == 4 and end_ip.version == 4:
                        result["objects"] = [literal]
                        result["values"] = [literal]
                        result["ipv4_values"] = [literal]
                        return result
                elif literal:
                    ip_value = ipaddress.ip_address(literal)
                    if ip_value.version == 4:
                        result["objects"] = [literal]
                        result["values"] = [literal]
                        result["ipv4_values"] = [literal]
                        return result
            except ValueError:
                pass

            if name_token in recursion_guard:
                result["unresolved"] = [name_token]
                return result

            if name_token in address_index:
                values = object_values(address_index[name_token])
                result["objects"] = [name_token]
                result["values"] = values
                result["ipv4_values"] = ipv4_only(values)
                return result

            if name_token in group_index:
                recursion_guard = set(recursion_guard)
                recursion_guard.add(name_token)

                group_obj = group_index[name_token]
                static_members = member_list(group_obj.get("static"))
                nested_results = [resolve_name(member, recursion_guard) for member in static_members]

                result["groups"] = [name_token]
                result["objects"] = [name_token]

                dynamic_filter = None
                dynamic_obj = group_obj.get("dynamic")
                if isinstance(dynamic_obj, dict):
                    dynamic_filter = dynamic_obj.get("filter")
                if dynamic_filter:
                    result["values"].append(f"dynamic:{dynamic_filter}")

                for nested in nested_results:
                    result["objects"].extend(nested["objects"])
                    result["groups"].extend(nested["groups"])
                    result["values"].extend(nested["values"])
                    result["ipv4_values"].extend(nested["ipv4_values"])
                    result["unresolved"].extend(nested["unresolved"])

                result["objects"] = dedupe(result["objects"])
                result["groups"] = dedupe(result["groups"])
                result["values"] = dedupe(result["values"])
                result["ipv4_values"] = dedupe(result["ipv4_values"])
                result["unresolved"] = dedupe(result["unresolved"])
                return result

            result["objects"] = [name_token]
            result["unresolved"] = [name_token]
            return result

        def resolve_members(members):
            aggregate = {
                "input_members": dedupe(members),
                "objects": [],
                "groups": [],
                "values": [],
                "ipv4_values": [],
                "unresolved": [],
            }
            for member in members:
                resolved = resolve_name(member)
                aggregate["objects"].extend(resolved["objects"])
                aggregate["groups"].extend(resolved["groups"])
                aggregate["values"].extend(resolved["values"])
                aggregate["ipv4_values"].extend(resolved["ipv4_values"])
                aggregate["unresolved"].extend(resolved["unresolved"])

            aggregate["objects"] = dedupe(aggregate["objects"])
            aggregate["groups"] = dedupe(aggregate["groups"])
            aggregate["values"] = dedupe(aggregate["values"])
            aggregate["ipv4_values"] = dedupe(aggregate["ipv4_values"])
            aggregate["unresolved"] = dedupe(aggregate["unresolved"])
            return aggregate

        merged_rules = []
        unresolved_total = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue

            source_members = member_list(rule.get("source"))
            destination_members = member_list(rule.get("destination"))

            source_resolved = resolve_members(source_members)
            destination_resolved = resolve_members(destination_members)

            unresolved_total.extend(source_resolved["unresolved"])
            unresolved_total.extend(destination_resolved["unresolved"])

            enriched_rule = dict(rule)
            enriched_rule["source_resolved"] = source_resolved
            enriched_rule["destination_resolved"] = destination_resolved
            merged_rules.append(enriched_rule)

        return {
            "rules": merged_rules,
            "summary": {
                "rule_count": len(merged_rules),
                "address_count": len(address_index),
                "address_group_count": len(group_index),
                "unresolved_objects": dedupe(unresolved_total),
            },
        }


    def get_operational_routing_table(self):
        '''
        Returns operational static/dynamic operational routing table.
        
        :param self: PanOS object
        '''
        rib_table = self.execute("show routing rib")  # RIB static route enumeration (Routing information base)
        fib_table = self.execute("show routing fib")  # FIB dynamic forwarding table (forwarding information base)

        rib_complete = bool(rib_table and rib_table.get("response", {}).get("result"))
        fib_complete = bool(fib_table and fib_table.get("response", {}).get("result"))

        return {
            "rib": {
                "complete": rib_complete,
                "response": rib_table,
            },
            "fib": {
                "complete": fib_complete,
                "response": fib_table,
            },
        }


    def get_rulebase(self):
        """
        Docstring for get_rulebase
        
        :param self: Description

        cmd: show rulebase security
        """
        vsys_entries = ensure_list(self.panos.config.devices.entry.vsys.entry)
        if not vsys_entries:
            raise ValueError("No vsys entries found in configuration")

        vsys_name = getattr(vsys_entries[0], "name", None) or "vsys1"
        xpath = f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/rulebase/security/rules"
        results = self.execute(api_type="config", api_action="get", api_xpath=xpath)
        if not isinstance(results, dict):
            return []

        result_block = results.get("response", {}).get("result")
        if not isinstance(result_block, dict):
            return []

        rules_block = result_block.get("rules")
        if not isinstance(rules_block, dict):
            return []

        entries = rules_block.get("entry")
        if entries is None:
            return []

        return ensure_list(entries)

    def get_addresses(self):
        """Returns addresses on PanOS Configuration"""
        vsys_entries = ensure_list(self.panos.config.devices.entry.vsys.entry)
        if not vsys_entries:
            raise ValueError("No vsys entries found in configuration")

        vsys_name = getattr(vsys_entries[0], "name", None) or "vsys1"
        xpath = f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/address"
        results = self.execute(api_type="config", api_action="get", api_xpath=xpath)
        if not isinstance(results, dict):
            return []

        result_block = results.get("response", {}).get("result")
        if not isinstance(result_block, dict):
            return []

        address_block = result_block.get("address")
        if not isinstance(address_block, dict):
            return []

        entries = address_block.get("entry")
        if entries is None:
            return []

        return ensure_list(entries)

    def get_address_groups(self):
        """Returns address groups on PanOS Configuration"""
        vsys_entries = ensure_list(self.panos.config.devices.entry.vsys.entry)
        if not vsys_entries:
            raise ValueError("No vsys entries found in configuration")

        vsys_name = getattr(vsys_entries[0], "name", None) or "vsys1"
        xpath = f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/address-group"
        results = self.execute(api_type="config", api_action="get", api_xpath=xpath)
        if not isinstance(results, dict):
            return []

        result_block = results.get("response", {}).get("result")
        if not isinstance(result_block, dict):
            return []

        group_block = result_block.get("address-group")
        if not isinstance(group_block, dict):
            return []

        entries = group_block.get("entry")
        if entries is None:
            return []

        return ensure_list(entries)

    def merge_rulebase_address_objects(self, rulebase=None, addresses=None, address_groups=None):
        """
        Resolves rulebase source/destination object names into object values and IPv4 values.
        """
        def dedupe(values):
            seen = set()
            ordered = []
            for value in values:
                try:
                    marker = ("hashable", value)
                    hash(marker)
                except TypeError:
                    marker = ("json", json.dumps(value, sort_keys=True, default=str))
                if marker in seen:
                    continue
                seen.add(marker)
                ordered.append(value)
            return ordered

        def member_list(block):
            if not isinstance(block, dict):
                return []
            members = block.get("member")
            if members is None:
                return []
            normalized = []
            for member in ensure_list(members):
                if isinstance(member, dict):
                    text_value = member.get("_text")
                    if text_value is None:
                        text_value = member.get("name")
                    if text_value is None:
                        text_value = json.dumps(member, sort_keys=True, default=str)
                    member = text_value
                text = str(member).strip()
                if text:
                    normalized.append(text)
            return normalized

        def object_values(addr_obj):
            values = []
            for key in ("ip-netmask", "ip-range", "fqdn"):
                value = addr_obj.get(key)
                if value:
                    values.append(value)
            return values

        def ipv4_only(values):
            out = []
            for value in values:
                candidate = str(value).split("/", 1)[0].split("-", 1)[0]
                try:
                    ip = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if ip.version == 4:
                    out.append(value)
            return out

        rules = ensure_list(rulebase if rulebase is not None else self.get_rulebase())
        addresses = ensure_list(addresses if addresses is not None else self.get_addresses())
        address_groups = ensure_list(address_groups if address_groups is not None else self.get_address_groups())

        address_index = {
            obj.get("name"): obj for obj in addresses
            if isinstance(obj, dict) and obj.get("name")
        }
        group_index = {
            obj.get("name"): obj for obj in address_groups
            if isinstance(obj, dict) and obj.get("name")
        }

        def resolve_name(name, recursion_guard=None):
            if recursion_guard is None:
                recursion_guard = set()

            name_token = name
            if isinstance(name_token, dict):
                extracted = name_token.get("_text")
                if extracted is None:
                    extracted = name_token.get("name")
                if extracted is None:
                    extracted = json.dumps(name_token, sort_keys=True, default=str)
                name_token = extracted
            if name_token is not None:
                name_token = str(name_token).strip()
                if not name_token:
                    name_token = None

            result = {
                "objects": [],
                "groups": [],
                "values": [],
                "ipv4_values": [],
                "unresolved": [],
            }

            if name_token in ("any", None):
                result["objects"] = [name_token]
                result["values"] = [name_token, "0.0.0.0/0"]
                result["ipv4_values"] = ["0.0.0.0/0"]
                return result

            # Direct literal destination/source members are valid PAN-OS selectors.
            try:
                literal = name_token
                if literal and "/" in literal:
                    network = ipaddress.ip_network(literal, strict=False)
                    if network.version == 4:
                        result["objects"] = [literal]
                        result["values"] = [literal]
                        result["ipv4_values"] = [literal]
                        return result
                elif literal and "-" in literal:
                    start_raw, end_raw = literal.split("-", 1)
                    start_ip = ipaddress.ip_address(start_raw.strip())
                    end_ip = ipaddress.ip_address(end_raw.strip())
                    if start_ip.version == 4 and end_ip.version == 4:
                        result["objects"] = [literal]
                        result["values"] = [literal]
                        result["ipv4_values"] = [literal]
                        return result
                elif literal:
                    ip_value = ipaddress.ip_address(literal)
                    if ip_value.version == 4:
                        result["objects"] = [literal]
                        result["values"] = [literal]
                        result["ipv4_values"] = [literal]
                        return result
            except ValueError:
                pass

            if name_token in recursion_guard:
                result["unresolved"] = [name_token]
                return result

            if name_token in address_index:
                values = object_values(address_index[name_token])
                result["objects"] = [name_token]
                result["values"] = values
                result["ipv4_values"] = ipv4_only(values)
                return result

            if name_token in group_index:
                recursion_guard = set(recursion_guard)
                recursion_guard.add(name_token)

                group_obj = group_index[name_token]
                static_members = member_list(group_obj.get("static"))
                nested_results = [resolve_name(member, recursion_guard) for member in static_members]

                result["groups"] = [name_token]
                result["objects"] = [name_token]

                dynamic_filter = None
                dynamic_obj = group_obj.get("dynamic")
                if isinstance(dynamic_obj, dict):
                    dynamic_filter = dynamic_obj.get("filter")
                if dynamic_filter:
                    result["values"].append(f"dynamic:{dynamic_filter}")

                for nested in nested_results:
                    result["objects"].extend(nested["objects"])
                    result["groups"].extend(nested["groups"])
                    result["values"].extend(nested["values"])
                    result["ipv4_values"].extend(nested["ipv4_values"])
                    result["unresolved"].extend(nested["unresolved"])

                result["objects"] = dedupe(result["objects"])
                result["groups"] = dedupe(result["groups"])
                result["values"] = dedupe(result["values"])
                result["ipv4_values"] = dedupe(result["ipv4_values"])
                result["unresolved"] = dedupe(result["unresolved"])
                return result

            result["objects"] = [name_token]
            result["unresolved"] = [name_token]
            return result

        def resolve_members(members):
            aggregate = {
                "input_members": dedupe(members),
                "objects": [],
                "groups": [],
                "values": [],
                "ipv4_values": [],
                "unresolved": [],
            }
            for member in members:
                resolved = resolve_name(member)
                aggregate["objects"].extend(resolved["objects"])
                aggregate["groups"].extend(resolved["groups"])
                aggregate["values"].extend(resolved["values"])
                aggregate["ipv4_values"].extend(resolved["ipv4_values"])
                aggregate["unresolved"].extend(resolved["unresolved"])

            aggregate["objects"] = dedupe(aggregate["objects"])
            aggregate["groups"] = dedupe(aggregate["groups"])
            aggregate["values"] = dedupe(aggregate["values"])
            aggregate["ipv4_values"] = dedupe(aggregate["ipv4_values"])
            aggregate["unresolved"] = dedupe(aggregate["unresolved"])
            return aggregate

        merged_rules = []
        unresolved_total = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue

            source_members = member_list(rule.get("source"))
            destination_members = member_list(rule.get("destination"))

            source_resolved = resolve_members(source_members)
            destination_resolved = resolve_members(destination_members)

            unresolved_total.extend(source_resolved["unresolved"])
            unresolved_total.extend(destination_resolved["unresolved"])

            enriched_rule = dict(rule)
            enriched_rule["source_resolved"] = source_resolved
            enriched_rule["destination_resolved"] = destination_resolved
            merged_rules.append(enriched_rule)

        return {
            "rules": merged_rules,
            "summary": {
                "rule_count": len(merged_rules),
                "address_count": len(address_index),
                "address_group_count": len(group_index),
                "unresolved_objects": dedupe(unresolved_total),
            },
        }


    def get_operational_routing_table(self):
        '''
        Returns operational static/dynamic operational routing table.
        
        :param self: PanOS object
        '''
        rib_table = self.execute("show routing rib")  # RIB static route enumeration (Routing information base)
        fib_table = self.execute("show routing fib")  # FIB dynamic forwarding table (forwarding information base)

        rib_complete = bool(rib_table and rib_table.get("response", {}).get("result"))
        fib_complete = bool(fib_table and fib_table.get("response", {}).get("result"))

        return {
            "rib": {
                "complete": rib_complete,
                "response": rib_table,
            },
            "fib": {
                "complete": fib_complete,
                "response": fib_table,
            },
        }


if __name__ == "__main__":
    import sys
    # if cli parameter is '--interactive', run interactive CLI on target.
    if len(sys.argv) > 1 and sys.argv[1] == '--interactive':
        if len(sys.argv) > 2 and sys.argv[2] is not None:
            endpoint = sys.argv[2]
        else:
            endpoint = input("Enter PanOS/Panorama IP/FQDN: ")

        try:
            creds = {
                "username": input("Username: "),
                "password": getpass.getpass("Password: ")
            }
            pano = EzPanOS(endpoint, username=creds["username"], password=creds["password"])

            print("Interactive PanOS CLI. Type 'exit' to quit.")

            while True:
                cmd = input(f"{creds.get('username')}@{endpoint}> ")
                if cmd.strip().lower() in ['exit', 'quit']:
                    break
                if not cmd.strip():
                    continue
                xml_cmd = build_xml_from_command(cmd)
                try:
                    responses = pano.batch_execute([xml_cmd])
                    for response in responses:
                        prettyprint_xml(response)
                except Exception as e:
                    print("Error:", e)
        except KeyboardInterrupt:
            print("\nExiting interactive CLI.")

    else:
        # print usage
        print("Script Usage: python3 panorama.py --interactive")
