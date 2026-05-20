from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from ezpanos.ezpanos import EzPanOS


@dataclass(init=False)
class Estate:
    """
    Collection of EzPanOS clients with estate-level operations.
    """

    config: str | dict[str, Any] | None
    profile: str
    devices: list["EzPanOS"] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        config: str | dict[str, Any] | None = None,
        profile: str = "default",
        devices: list["EzPanOS"] | None = None,
        metadata: dict[str, Any] | None = None,
        include_unavailable: bool = False,
        connect_on_init: bool = True,
        expand_panorama: bool = True,
        include_panorama_controllers: bool = True,
        client_factory: Callable[..., "EzPanOS"] | None = None,
        auto_build: bool | None = None,
    ) -> None:
        resolved_config = config
        resolved_profile = profile if profile is not None else "default"

        self.config = resolved_config
        self.profile = resolved_profile
        self.devices = list(devices) if devices is not None else []
        self.metadata = dict(metadata) if metadata is not None else {}

        if auto_build is None:
            auto_build = bool(resolved_config) and devices is None
        if not auto_build:
            return
        if not resolved_config:
            raise ValueError("config is required when auto_build=True")

        built_devices, built_metadata = self._build_from_config_profile(
            config_path=resolved_config,
            config_profile=resolved_profile,
            include_unavailable=include_unavailable,
            connect_on_init=connect_on_init,
            expand_panorama=expand_panorama,
            include_panorama_controllers=include_panorama_controllers,
            client_factory=client_factory,
        )
        self.devices = built_devices
        self.metadata = built_metadata

    def available_devices(self) -> list["EzPanOS"]:
        return [device for device in self.devices if getattr(device, "connected", False)]

    def by_role(self, role: str) -> list["EzPanOS"]:
        role_text = str(role or "").strip().lower()
        if not role_text:
            return []
        return [device for device in self.devices if str(getattr(device, "estate_role", "")).strip().lower() == role_text]

    def execute_all(self, command: str, **kwargs) -> dict[str, Any]:
        """
        Convenience higher-order operation for broadcasting one command.
        """
        results = {}
        for device in self.devices:
            estate_id = str(getattr(device, "estate_id", getattr(device, "endpoint", "unknown-device")))
            results[estate_id] = device.execute(command=command, **kwargs)
        return results

    @classmethod
    def _build_from_config_profile(
        cls,
        config_path: str | dict[str, Any],
        config_profile: str = "default",
        include_unavailable: bool = False,
        connect_on_init: bool = True,
        expand_panorama: bool = True,
        include_panorama_controllers: bool = True,
        client_factory: Callable[..., "EzPanOS"] | None = None,
    ) -> tuple[list["EzPanOS"], dict[str, Any]]:
        from ezpanos.ezpanos import EzPanOS
        from ezpanos.utils import ensure_list

        client_factory = client_factory or EzPanOS
        config_data: dict[str, Any]
        config_path_for_clients: str | None
        if isinstance(config_path, str):
            config_data = EzPanOS._load_config_data(config_path)
            config_path_for_clients = config_path
        elif isinstance(config_path, dict):
            config_data = config_path
            config_path_for_clients = None
        else:
            raise TypeError("config must be a file path string or a dict")

        profile_block = EzPanOS._resolve_config_block(config_data, endpoint=None, config_profile=config_profile)

        default_username = EzPanOS._coalesce_config_string(profile_block, "username", "user")
        default_password = EzPanOS._coalesce_config_string(profile_block, "password")
        entries = EzPanOS._normalize_profile_endpoint_entries(profile_block)
        if not entries:
            raise ValueError(f"profile `{config_profile}` contains no endpoint entries")

        instances = []
        seen_ids = set()

        def add_instance(instance: "EzPanOS", endpoint_hint: str | None = None) -> None:
            estate_id = str(getattr(instance, "estate_id", None) or getattr(instance, "endpoint", "unknown-device"))
            if estate_id in seen_ids:
                return
            if instance.connected or include_unavailable or (not connect_on_init):
                seen_ids.add(estate_id)
                instances.append(instance)
            else:
                endpoint_text = endpoint_hint or getattr(instance, "endpoint", "unknown-endpoint")
                print(f"Warning: skipping unavailable endpoint {endpoint_text}: {instance.connection_error}")

        for index, entry in enumerate(entries, start=1):
            endpoint = EzPanOS._coalesce_config_string(entry, "endpoint", "firewall_endpoint")
            if not endpoint:
                continue

            username, password = EzPanOS._entry_auth_tuple(
                entry=entry,
                default_username=default_username,
                default_password=default_password,
            )
            instance = client_factory(
                endpoint=endpoint,
                username=username,
                password=password,
                config_path=config_path_for_clients,
                config_profile=config_profile if config_path_for_clients else None,
                connect_on_init=connect_on_init,
                fail_on_init_error=False,
            )
            if config_path_for_clients is None:
                instance.policy_defaults = EzPanOS._resolve_policy_defaults_for_endpoint(profile_block, instance.endpoint)
                instance.api_defaults = EzPanOS._resolve_api_defaults_for_endpoint(profile_block, instance.endpoint)
                instance.request_timeout_default = EzPanOS._resolve_timeout_setting(
                    explicit_value=None,
                    env_var="EZPANOS_REQUEST_TIMEOUT",
                    config_block=instance.api_defaults,
                    config_key="request_timeout",
                    default=30.0,
                )
                instance.keygen_request_timeout = EzPanOS._resolve_timeout_setting(
                    explicit_value=None,
                    env_var="EZPANOS_KEYGEN_TIMEOUT",
                    config_block=instance.api_defaults,
                    config_key="keygen_timeout",
                    default=instance.request_timeout_default,
                )

            is_panorama_entry = bool(expand_panorama and EzPanOS._looks_like_panorama_entry(entry, profile_block=profile_block))
            role = "panorama-controller" if is_panorama_entry else "firewall"
            if not getattr(instance, "estate_id", None) or getattr(instance, "estate_id", None) == instance.endpoint:
                instance.estate_id = EzPanOS._build_estate_id(
                    endpoint=instance.endpoint,
                    role=role,
                    profile=config_profile,
                    entry_index=index,
                )
            instance.estate_role = role
            instance.panorama_controller_id = instance.estate_id if is_panorama_entry else None
            instance.panorama_controller_endpoint = instance.endpoint if is_panorama_entry else None
            instance.panorama_managed_serial = None
            instance.panorama_device_groups = []
            instance.panorama_templates = []
            instance.panorama_template_stacks = []

            if (not is_panorama_entry) or include_panorama_controllers:
                add_instance(instance, endpoint_hint=endpoint)

            if not is_panorama_entry:
                continue

            if not instance.connected:
                if connect_on_init:
                    continue
                if not instance.ensure_connected(fail_on_error=False):
                    continue

            try:
                discovery = instance.discover_panorama_managed_devices(
                    include_templates=True,
                    include_raw=False,
                )
            except Exception as exc:
                print(f"Warning: panorama discovery failed for {instance.endpoint}: {exc}")
                continue

            controller_id = str(getattr(instance, "estate_id", instance.endpoint))
            discovered_devices = ensure_list(discovery.get("managed_devices"))
            for discovered_index, managed in enumerate(discovered_devices, start=1):
                if not isinstance(managed, dict):
                    continue

                managed_endpoint = EzPanOS._coalesce_payload_string(
                    managed,
                    "endpoint",
                    "ip-address",
                    "ip_address",
                    "management-ip",
                    "management_ip",
                    "mgmt-ip",
                    "mgmt_ip",
                )
                if not managed_endpoint:
                    continue

                managed_serial = EzPanOS._coalesce_payload_string(managed, "serial", "name", "deviceid", "device-id")
                managed_hostname = EzPanOS._coalesce_payload_string(managed, "hostname", "host-name")

                managed_username, managed_password = EzPanOS._entry_auth_tuple(
                    entry=entry,
                    default_username=default_username,
                    default_password=default_password,
                )
                if managed_username is None:
                    managed_username = instance.username
                if managed_password is None:
                    managed_password = instance.password

                managed_instance = client_factory(
                    endpoint=managed_endpoint,
                    username=managed_username,
                    password=managed_password,
                    config_path=config_path_for_clients,
                    config_profile=config_profile if config_path_for_clients else None,
                    connect_on_init=connect_on_init,
                    fail_on_init_error=False,
                )
                if config_path_for_clients is None:
                    managed_instance.policy_defaults = EzPanOS._resolve_policy_defaults_for_endpoint(profile_block, managed_instance.endpoint)
                    managed_instance.api_defaults = EzPanOS._resolve_api_defaults_for_endpoint(profile_block, managed_instance.endpoint)
                    managed_instance.request_timeout_default = EzPanOS._resolve_timeout_setting(
                        explicit_value=None,
                        env_var="EZPANOS_REQUEST_TIMEOUT",
                        config_block=managed_instance.api_defaults,
                        config_key="request_timeout",
                        default=30.0,
                    )
                    managed_instance.keygen_request_timeout = EzPanOS._resolve_timeout_setting(
                        explicit_value=None,
                        env_var="EZPANOS_KEYGEN_TIMEOUT",
                        config_block=managed_instance.api_defaults,
                        config_key="keygen_timeout",
                        default=managed_instance.request_timeout_default,
                    )
                managed_instance.estate_role = "panorama-managed-firewall"
                managed_instance.estate_id = EzPanOS._build_estate_id(
                    endpoint=managed_endpoint,
                    role="panorama-managed-firewall",
                    controller_id=controller_id,
                    serial=managed_serial,
                    profile=config_profile,
                    entry_index=discovered_index,
                )
                managed_instance.panorama_controller_id = controller_id
                managed_instance.panorama_controller_endpoint = instance.endpoint
                managed_instance.panorama_managed_serial = managed_serial
                managed_instance.panorama_managed_hostname = managed_hostname
                managed_instance.panorama_device_groups = ensure_list(managed.get("device_groups"))
                managed_instance.panorama_templates = ensure_list(managed.get("templates"))
                managed_instance.panorama_template_stacks = ensure_list(managed.get("template_stacks"))

                add_instance(managed_instance, endpoint_hint=managed_endpoint)

        if not instances:
            print(f"Warning: profile `{config_profile}` has no available endpoints")

        metadata = {
            "expand_panorama": bool(expand_panorama),
            "include_unavailable": bool(include_unavailable),
            "include_panorama_controllers": bool(include_panorama_controllers),
            "connect_on_init": bool(connect_on_init),
        }
        return instances, metadata

    @classmethod
    def from_config_profile(
        cls,
        config_path: str,
        config_profile: str = "default",
        include_unavailable: bool = False,
        connect_on_init: bool = True,
        expand_panorama: bool = True,
        include_panorama_controllers: bool = True,
        client_factory: Callable[..., "EzPanOS"] | None = None,
    ) -> "Estate":
        return cls(
            config=config_path,
            profile=config_profile,
            include_unavailable=include_unavailable,
            connect_on_init=connect_on_init,
            expand_panorama=expand_panorama,
            include_panorama_controllers=include_panorama_controllers,
            client_factory=client_factory,
            auto_build=True,
        )
