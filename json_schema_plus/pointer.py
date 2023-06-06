from typing import List, Union

from .exception import JsonSchemaPlusException


class JsonPointer:
    def __init__(self, elements: List[Union[str, int]] = []) -> None:
        self.elements = elements

    def __add__(self, other: str) -> "JsonPointer":
        if isinstance(other, str) or isinstance(other, int):
            return JsonPointer(self.elements + [other])
        raise JsonSchemaPlusException(f"Can only add str or int, got {other}")

    def is_root(self) -> bool:
        return len(self.elements) == 0

    def __str__(self) -> str:
        return "#/" + "/".join([str(i) for i in self.elements])
    
    def __repr__(self) -> str:
        return str(self)
