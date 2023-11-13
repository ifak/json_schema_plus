from typing import List, Union

from .exception import JsonPointerException


def escape(s: str):
    return s.replace("~", "~0").replace("/", "~1").replace("%25", "%")


def unescape(s: str):
    return s.replace("%25", "%").replace("~1", "/").replace("~0", "~")


class JsonPointer:
    def __init__(self, elements: List[Union[str, int]] = None) -> None:
        self.elements = elements or []

    def __add__(self, other: str) -> "JsonPointer":
        if isinstance(other, str) or isinstance(other, int):
            return JsonPointer(self.elements + [other])
        elif isinstance(other, list):
            result = self
            for i in other:
                result = result + i
            return result
        raise JsonPointerException(f"Can only add str or int, got {other}")

    def is_root(self) -> bool:
        return len(self.elements) == 0

    def __str__(self) -> str:
        return "#/" + "/".join([escape(str(i)) for i in self.elements])

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def from_string(self, value: str) -> "JsonPointer":
        if value == '#/' or value == '#':
            return JsonPointer()

        if not value.startswith('#/'):
            raise Exception(f"Only local pointers are supported, got {value}")
        value = value[2:]
        elements = [unescape(i) for i in value.split("/")]
        return JsonPointer(elements)

    def lookup(self, data: any, index: int = 0) -> any:
        if index > len(self.elements):
            raise JsonPointerException("Out of range")
        if index == len(self.elements):
            return data
        if isinstance(data, dict):
            key = self.elements[index]
            try:
                value = data[key]
            except KeyError:
                raise JsonPointerException(f"{key} not in data")
            return self.lookup(value, index+1)
        elif isinstance(data, list):
            try:
                i = int(self.elements[index])
            except ValueError:
                raise JsonPointerException(f"{self.elements[index]} is not an integer for array lookup")
            try:
                value = data[i]
            except IndexError:
                raise JsonPointerException(f"Index not in array")
            return self.lookup(data[i], index+1)
        else:
            raise JsonPointerException(f"Cannot lookup in {data}")
