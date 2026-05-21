# EZPanOS
lightweight PAN-OS utility library focused on practical operational tasks.

## Why `ezpanos` exists

`ezpanos` is not a replacement for Palo Alto Networks’ official SDKs.

It grew out of working directly with PAN-OS automation and seeing how often engineers still end up dealing with hardcoded XPath, XML-heavy responses, and task-specific parsing logic.

`ezpanos` exists to make that experience more practical.

The PAN-OS ecosystem exposes strong configuration and object-management primitives, but real-world operational automation require lower-level PanOS command execution and response parsing-- making operations requiring application logic more intuitive to build.

Right now, the CLI and execution interfaces return JSON. Higher-order abstractions on objects introduce maintenance overhead. This is more of an execution and translation layer for higher-order automations and projects.

The goal is to make operational automation easier to read and build.

## Installation
```bash
pip install ezpanos
```

## Quick Start
```python
from ezpanos import EzPanOS

endpoint = "10.0.0.1"
fw = EzPanOS(endpoint=endpoint, username="admin")
print(fw.execute("show system info"))
```

For slower systems/commands, raise the default API timeout:
```python
fw = EzPanOS(endpoint=endpoint, username="admin", request_timeout_default=90)
```

If password is omitted, you are prompted.
Credential precedence is deterministic: explicit `username/password` arguments are used first, then config profile values, then interactive prompt for missing values.

## Config Profiles
You can use a `config.json` file for endpoint/profile organization and optional usernames/passwords.

Conceptually, an `estate` is the firewalls you intend to manage. Because the utility works on many PanOS Configuration types: Panorama, Firewall, or Log Collector: each can be assimilated into this framework.

Example `config.json`:
```json
{
  "profiles": {
    "estate": {
      "username": "svc_firewall",
      "endpoints": [
        {"endpoint": "firewall-1.inside.example.com"},
        {"endpoint": "firewall-2.inside.example.com"}
      ]
    }
  }
}
```

Build an estate object:
```python
from ezpanos.estate import Estate

estate = Estate(
    config="config.json",
    profile="estate",
)

for device in estate.devices:
    print(device.endpoint, device.estate_role)
```
`estate` is a concrete `ezpanos.Estate` instance that directly owns a list of `EzPanOS` devices.

You can also pass a parsed config dictionary directly:
```python
from ezpanos.estate import Estate

config = {
    "profiles": {
        "production": {
            "username": "svc_firewall",
            "endpoints": [
                {"endpoint": "firewall-1.inside.example.com"},
                {"endpoint": "firewall-2.inside.example.com"}
            ]
        }
    }
}

estate = Estate(
    config=config,
    profile="production",
)
```

Note that the `profile` value is configurable if you intend to logically separate the management of different such estates. This is useful for environments with multiple Panorama instances.

If passwords are not present in config, you will be prompted.

To apply a command to a Estate:
```python
from ezpanos.estate import Estate

estate = Estate(
    config="config.json",
    profile="estate",
)


# Example Software upgrade/installation workflow:

# will make all firewalls request a system update
estate.execute_all("request system software check")

# will download a specific version of PanOS
estate.execute_all("request system software download version <version>")

# will install a specific version of PanOS
estate.execute_all("request system software install version <version>")

# will reboot firewalls
estate.execute_all("request restart system")

```

## Rule Management
```python
from ezpanos import EzPanOS

fw = EzPanOS(endpoint="10.0.0.1", username="admin")
result = fw.create_security_rule(
    rule_name="example-rule",
    from_zones=["trust"],
    to_zones=["untrust"],
    sources=["any"],
    destinations=["any"],
    applications=["web-browsing"],
    services=["application-default"],
    action="allow",
)
print(result)
```

Delete rule and commit:
```python
delete_result = fw.delete_security_rule("example-rule", ignore_missing=True)
print(delete_result)

commit_result = fw.commit(wait_for_job=True)
print(commit_result)
```

## Job sensitive commands
Some commands like software download/install as well as standard commit jobs execute beyond the xml command success.

To monitor the job id of an executed command:
```python
response = fw.execute("request sustem software download 11.1.6-h3")
job_id = fw.extract_job_id(response)

# Or likewise:

version = "10.1.1"
response = fw.execute(f"request sustem software download version: {version}")
job_id = fw.extract_job_id(response)

This job can then be monitored with
response = fw.execute(f"show jobs id {job_id}")
```
