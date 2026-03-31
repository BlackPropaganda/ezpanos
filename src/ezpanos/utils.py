import datetime
import ipaddress
import keyword
import xml.etree.ElementTree as ET


def xml_string_to_dict(xml_string: str):
    root = ET.fromstring(xml_string)
    return {root.tag: _element_to_dict(root)}


def xml_file_to_dict(path):
    tree = ET.parse(path)
    root = tree.getroot()
    return {root.tag: _element_to_dict(root)}


def _element_to_dict(element):
    """
    Recursively convert an XML element into a dict,
    preserving attributes and text.
    """
    result = {}

    # 1. Include attributes first
    if element.attrib:
        for k, v in element.attrib.items():
            result[k] = v

    # 2. Leaf node (no children)
    if len(element) == 0:
        text = element.text.strip() if element.text else None
        if text:
            if result:
                # If there are attributes, store text under "_text"
                result["_text"] = text
            else:
                return text
        return result if result else None

    # 3. Process child elements
    for child in element:
        value = _element_to_dict(child)

        if child.tag in result:
            # Convert to list if multiple children with same tag
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(value)
        else:
            result[child.tag] = value

    return result


def contained_in(target: str, interface_cidr: str) -> bool:
    """
    Check whether an IP or subnet is contained within an interface subnet.

    Examples:
      contained_in("10.0.0.3", "10.0.0.1/24")   -> True
      contained_in("10.0.0.1/24", "10.0.0.0/8") -> True
    """
    interface_net = ipaddress.ip_network(interface_cidr, strict=False)

    # Case 1: target is an IP
    try:
        target_ip = ipaddress.ip_address(target)
        return target_ip in interface_net
    except ValueError:
        pass

    # Case 2: target is a subnet
    try:
        target_net = ipaddress.ip_network(target, strict=False)
        return target_net.subnet_of(interface_net)
    except ValueError:
        pass

    raise ValueError(f"Invalid target: {target}")


def get_current_time_string():
    return datetime.datetime.now().strftime("%Y_%m_%d_%H:%M:%S")


def sanitize_field_name(name: str) -> str:
    """
    Convert XML/dict key to valid Python identifier:
    - Replace '-' with '_'
    - Append '_' if it is a Python keyword
    """
    sanitized = name.replace("-", "_")
    if keyword.iskeyword(sanitized):
        sanitized += "_"
    return sanitized


def ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


__all__ = [
    "xml_string_to_dict",
    "xml_file_to_dict",
    "contained_in",
    "get_current_time_string",
    "sanitize_field_name",
    "ensure_list",
]
