from typing import Union, Dict, Any, List, Set
from enum import Enum
from .exception import TypeException

JsonValue = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]


class JsonType(Enum):
    NULL = 'null'
    BOOLEAN = 'boolean'
    NUMBER = 'number'
    INTEGER = 'integer'
    STRING = 'string'
    ARRAY = 'array'
    OBJECT = 'object'

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return str(self)


ALL_JSON_TYPES = set([i for i in JsonType])

JsonTypes = Set[JsonType]


def from_instance(instance: JsonValue) -> JsonTypes:
    if isinstance(instance, dict):
        return {JsonType.OBJECT}
    if isinstance(instance, list):
        return {JsonType.ARRAY}
    if isinstance(instance, str):
        return {JsonType.STRING}
    if instance is True or instance is False:
        return {JsonType.BOOLEAN}
    if instance is None:
        return {JsonType.NULL}
    if isinstance(instance, int):
        return {JsonType.INTEGER, JsonType.NUMBER}
    if isinstance(instance, float):
        if int(instance) == instance:
            return {JsonType.INTEGER, JsonType.NUMBER}
        return {JsonType.NUMBER}
    raise TypeException(f"Cannot infer type from instance '{instance}'")


def from_typename(typename: str) -> JsonTypes:
    try:
        return set([JsonType(typename)])
    except ValueError:
        raise TypeException(f"Invalid typename {typename}")


def values_are_equal(a: JsonValue, b: JsonValue) -> bool:
    if isinstance(a, list):
        if not isinstance(b, list):
            return False
        if len(a) != len(b):
            return False
        for av, bv in zip(a, b):
            if not values_are_equal(av, bv):
                return False
        return True
    elif isinstance(a, dict):
        if not isinstance(b, dict):
            return False
        if len(a.keys()) != len(b.keys()):
            return False
        for k, v in a.items():
            if k not in b:
                return False
            if not values_are_equal(v, b[k]):
                return False
        return True
    # Boolean needs special handling here since isinstance(False, int) holds
    elif a is False:
        return b is False
    elif a is True:
        return b is True
    elif b is False:
        return a is False
    elif b is True:
        return a is True
    elif isinstance(a, (int, float)):
        if not isinstance(b, (int, float)):
            return False
        return a == b
    elif isinstance(a, str):
        if not isinstance(b, str):
            return False
        return a == b
    elif a is None and b is None:
        return True
    else:
        return False
