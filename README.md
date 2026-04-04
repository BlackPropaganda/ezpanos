# EZPanOS
lightweight PAN-OS utility library focused on practical operational tasks.

## Why `ezpanos` exists

`ezpanos` is not a replacement for Palo Alto Networks’ official SDKs.


It grew out of working directly with PAN-OS automation and seeing how often engineers still end up dealing with hardcoded XPath, XML-heavy responses, and task-specific parsing logic.

`ezpanos` exists to make that experience more practical.

The PAN-OS ecosystem exposes strong configuration and object-management primitives, but real-world automation often needs more than object CRUD:
* intuitive command execution
* JSON-normalized output
* Multi-device and Panorama-oriented workflows

The goal is to make operational automation easier to build, read, and reuse.

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

If password is omitted, you are securely prompted. Credentials entered once can be reused in-memory for subsequent connections in the same run.

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

Build instances:
```python
from ezpanos import EzPanOS

instances = EzPanOS.instances_from_config_profile(
    config_path="config.json",
    config_profile="estate",
)
```

Note that the name of the `config_profile` is `estate`, this is configurable if you intend to logically separate the management of different such estates. This is useful for environments with multiple Panorama Instances.

If passwords are not present in config, you will be prompted and values are reused from in-memory cache where possible.

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
