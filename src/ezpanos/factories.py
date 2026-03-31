from ezpanos.models import *
from ezpanos.utils import sanitize_field_name

from dataclasses import dataclass, field, make_dataclass, is_dataclass, fields
import keyword
from typing import Any, Dict, List
from typing import Any


def dict_to_dataclass(name: str, data: dict) -> Any:
    fields_list = []
    values = {}

    for key, value in data.items():
        field_name = sanitize_field_name(key)

        if isinstance(value, dict):
            sub_dc = dict_to_dataclass(f"{name}_{field_name}", value)
            fields_list.append((field_name, type(sub_dc)))
            values[field_name] = sub_dc

        elif isinstance(value, list):
            if value and all(isinstance(v, dict) for v in value):
                sub_list = [dict_to_dataclass(f"{name}_{field_name}", v) for v in value]
                fields_list.append((field_name, List[type(sub_list[0])]))
                values[field_name] = sub_list
            else:
                fields_list.append((field_name, List[Any]))
                values[field_name] = value
        else:
            fields_list.append((field_name, Any))
            values[field_name] = value

    DC = make_dataclass(name, fields_list, frozen=False)
    return DC(**values)


def dataclass_to_dict(obj: Any, revert_keywords: bool = True) -> dict:
    """
    Recursively convert a dataclass instance back into a dictionary.
    
    Parameters:
        obj: dataclass instance
        revert_keywords: if True, will remove trailing underscores from keywords
    """
    if not is_dataclass(obj):
        return obj  # primitive type or list handled elsewhere

    result = {}
    for f in fields(obj):
        value = getattr(obj, f.name)

        # revert Python keyword suffix if requested
        key = f.name
        if revert_keywords and key.endswith("_") and keyword.iskeyword(key[:-1]):
            key = key[:-1]

        # recursively handle dataclasses
        if is_dataclass(value):
            result[key] = dataclass_to_dict(value, revert_keywords)
        elif isinstance(value, list):
            new_list = []
            for item in value:
                if is_dataclass(item):
                    new_list.append(dataclass_to_dict(item, revert_keywords))
                else:
                    new_list.append(item)
            result[key] = new_list
        else:
            result[key] = value
    return result
