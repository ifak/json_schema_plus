from json_schema_plus.types import JsonType, JsonValue
from .types import from_typename, JsonType, from_instance, values_are_equal, JsonTypes, ALL_JSON_TYPES
from .pointer import JsonPointer

from typing import Dict, List, Optional, Set, Callable, Pattern, Tuple
from .exception import InvalidSchemaException, TypeException, JsonPointerException

from io import FileIO
import re
from dataclasses import dataclass, field
import warnings
import operator


@dataclass
class ValidationConfig:

    preprocessor: Optional[Callable] = None
    short_circuit_evaluation: bool = False


@dataclass
class ParseConfig:

    format_validators: Dict[str, Callable[[str], bool]] = field(default_factory=dict)
    raise_on_unknown_format: bool = True


class KeywordValidationResult:

    def __init__(self, sub_pointer: List[str], sub_schema_results: List["SchemaValidationResult"] = None, error_message: Optional[str] = None):
        self.sub_pointer = sub_pointer
        self.sub_schema_results = sub_schema_results or []
        self.error_message = error_message

    def ok(self) -> bool:
        return self.error_message is None

    def dump(self, indent: int):
        if self.error_message is None:
            print("  " * indent + "<OK>")
        else:
            print("  " * indent + self.error_message)
        for i in self.sub_schema_results:
            i.dump(indent+1)

    def __repr__(self) -> str:
        return "OK" if self.ok() else "Fail!"

class SchemaValidationResult:
    def __init__(self, validator: "SchemaValidator", sub_results: List[KeywordValidationResult]) -> None:
        self.validator = validator
        self.sub_results = sub_results
        if len(self.sub_results) == 0:
            self.ok = True
        else:
            self.ok = all([i.ok() for i in self.sub_results])

    def dump(self, indent=0):
        print("  " * indent + f"{self.validator.pointer}:")
        for result in self.sub_results:
            result.dump(indent+1)


class _NoDefault:
    pass


class KeywordsValidator:
    """
    Validates an instance against one or more keywords in a schema
    """

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        self.parent = parent
        self.types: JsonType = None

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        raise NotImplementedError(f"{self}")


class NotValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        n = self.parent._read_any('not', unparsed_keys)
        self.sub_validator = SchemaValidator(n, self.parent.pointer + 'not', self.parent.root)
        self.types = self.sub_validator.types

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        sub_result = self.sub_validator._invoke(instance, config)
        if sub_result.ok():
            return [KeywordValidationResult(['not'], [sub_result], "Sub-schema must not be valid")]
        else:
            return [KeywordValidationResult(['not'], [sub_result])]


class IfThenElseValidator(KeywordsValidator):

    def __get_validator(self, kw: str, unparsed_keys: Set[str]) -> Optional["SchemaValidator"]:
        if kw in self.parent.schema:
            schema = self.parent._read_any(kw, unparsed_keys)
            return SchemaValidator(schema, self.parent.pointer + kw, self.parent.root)
        else:
            return None

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.if_validator = self.__get_validator('if', unparsed_keys)
        self.then_validator = self.__get_validator('then', unparsed_keys)
        self.else_validator = self.__get_validator('else', unparsed_keys)
        self.types = set()
        if self.then_validator:
            self.types |= self.then_validator.types
        if self.else_validator:
            self.types |= self.else_validator.types

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        # This is valid iff:
        # (not(IF) or THEN) and (IF or ELSE)
        # See https://json-schema.org/understanding-json-schema/reference/conditionals.html#implication

        if not self.if_validator:
            return []

        # Shorthand case: IF without THEN and ELSE is always valid
        if self.then_validator is None and self.else_validator is None:
            return [KeywordValidationResult(['if'])]

        if_result = self.if_validator._invoke(instance, config)

        if if_result.ok:
            if self.then_validator:
                then_result = self.then_validator._invoke(instance, config)
                if not then_result.ok:
                    return [KeywordValidationResult(['if'], [if_result, then_result], f"IF is valid but THEN is invalid")]
        else:
            if self.else_validator:
                else_result = self.else_validator._invoke(instance, config)
                if not else_result.ok:
                    return [KeywordValidationResult(['if'], [if_result, else_result], f"IF is invalid but ELSE is invalid")]

        return [KeywordValidationResult(['if'], [if_result])]


class AggregatingValidator(KeywordsValidator):
    """
    Base class for allOf, anyOf and oneOf validators
    """
    keyword = ''

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        l = self.parent._read_list(self.keyword, unparsed_keys)
        self.sub_validators: List[SchemaValidator] = []
        for idx, sub_schema in enumerate(l):
            sv = SchemaValidator(sub_schema, self.parent.pointer + self.keyword + idx, self.parent.root)
            self.sub_validators.append(sv)
        if not self.sub_validators:
            raise InvalidSchemaException(f"Must specify at least one sub-schema", self.parent.pointer)


class AllOfValidator(AggregatingValidator):

    keyword = 'allOf'

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES.copy()
        for i in self.sub_validators:
            self.types &= i.types
        if not self.types:
            warnings.warn(f"Found allOf, where Sub-schemas do not share a common type: always rejecting ({self.parent.pointer})")

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        sub_results: List[SchemaValidationResult] = []
        ok = True
        for validators in self.sub_validators:
            result = validators._invoke(instance, config)
            if not result.ok:
                ok = False
                if config.short_circuit_evaluation:
                    break
            sub_results.append(result)
        if ok:
            return [KeywordValidationResult([self.keyword], sub_results)]
        else:
            return [KeywordValidationResult([self.keyword], sub_results, "Does not match all sub-schemas")]


class AnyOfValidator(AggregatingValidator):

    keyword = 'anyOf'

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = set()
        for sub_validator in self.sub_validators:
            self.types |= sub_validator.types

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        sub_results: List[SchemaValidationResult] = []
        ok = False
        for validators in self.sub_validators:
            result = validators._invoke(instance, config)
            if result.ok:
                ok = True
                if config.short_circuit_evaluation:
                    break
            sub_results.append(result)
        if ok:
            return [KeywordValidationResult([self.keyword], sub_results)]
        else:
            return [KeywordValidationResult([self.keyword], sub_results, "Does not match at least one sub-schema")]


class OneOfValidator(AggregatingValidator):

    keyword = 'oneOf'

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = set()
        for sub_validator in self.sub_validators:
            self.types |= sub_validator.types

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        sub_schema_results: List[SchemaValidationResult] = []
        num_ok = 0
        for validators in self.sub_validators:
            result = validators._invoke(instance, config)
            sub_schema_results.append(result)
            if result.ok:
                num_ok += 1
        if num_ok == 1:
            return [KeywordValidationResult([self.keyword], sub_schema_results)]
        else:
            return [KeywordValidationResult([self.keyword], sub_schema_results, "Does not match exactly one sub-schema")]


class ReferenceValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.ref = self.parent._read_string('$ref', unparsed_keys)
        try:
            pointer = JsonPointer.from_string(self.ref)
        except JsonPointerException as e:
            raise InvalidSchemaException(f"Invalid JSON pointer: {e}")

        try:
            self.ref_validator = parent.root.validators_by_pointer[str(pointer)]
        except KeyError:
            ref_schema = pointer.lookup(self.parent.root.schema)
            self.ref_validator = SchemaValidator(ref_schema, pointer, self.parent.root)

        self.types = self.ref_validator.types

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        ref_result = self.ref_validator._invoke(instance, config)
        if ref_result.ok:
            return [KeywordValidationResult(['$ref'], [ref_result])]
        else:
            return [KeywordValidationResult(['$ref'], [ref_result], f"Reference {self.ref} is invalid")]


class ConstValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        unparsed_keys.remove('const')
        self.value = parent.schema['const']
        self.types = from_instance(self.value)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if values_are_equal(self.value, instance):
            return [KeywordValidationResult(['const'])]
        else:
            return [KeywordValidationResult(['const'], [], f"{instance} is not {self.value}")]


class StringPatternValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES

        pattern = self.parent._read_string('pattern', unparsed_keys)
        self.pattern: Pattern = re.compile(pattern)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, str):
            return []

        if self.pattern.search(instance) is None:
            return [KeywordValidationResult(['pattern'], [], f"Value does not match pattern")]
        else:
            return [KeywordValidationResult(['pattern'])]


class StringMinLengthValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        self.min_length = self.parent._read_float('minLength', unparsed_keys)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, str):
            return []

        if len(instance) >= self.min_length:
            return [KeywordValidationResult(['minLength'])]
        else:
            return [KeywordValidationResult(['minLength'], [], f"Value is shorter than {self.min_length}")]


class StringMaxLengthValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        self.max_length = self.parent._read_float('maxLength', unparsed_keys)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, str):
            return []

        if len(instance) <= self.max_length:
            return [KeywordValidationResult(['maxLength'])]
        else:
            return [KeywordValidationResult(['maxLength'], [], f"Value is longer than {self.max_length}")]


class StringFormatValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        self.format_name = self.parent._read_string('format', unparsed_keys)
        try:
            self.format_validator = self.parent.root.parse_config.format_validators[self.format_name]
        except KeyError:
            if self.parent.root.parse_config.raise_on_unknown_format:
                raise InvalidSchemaException(f"Unknown format {self.format_name}")

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, str):
            return []
        if self.format_validator(instance):
            return [KeywordValidationResult(['format'])]
        else:
            return [KeywordValidationResult(['format'], [], f'invalid format, should be {self.format_name}')]


class NumberLimitValidator(KeywordsValidator):

    operator = None
    keyword = ''
    message = ''

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.limit = self.parent._read_float(self.keyword, unparsed_keys)
        self.types = ALL_JSON_TYPES

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, (int, float)):
            return []

        if self.operator(instance, self.limit):
            return [KeywordValidationResult([self.keyword])]
        else:
            return [KeywordValidationResult([self.keyword], [], self.message.format(self.limit))]


class NumberMaximumValidator(NumberLimitValidator):
    operator = operator.le
    keyword = 'maximum'
    message = 'must be less than {}'


class NumberExclusiveMaximumValidator(NumberLimitValidator):
    operator = operator.lt
    keyword = 'exclusiveMaximum'
    message = 'must be less than {}'


class NumberMinimumValidator(NumberLimitValidator):
    operator = operator.ge
    keyword = 'minimum'
    message = 'must be greater than {}'


class NumberExclusiveMinimumValidator(NumberLimitValidator):
    operator = operator.gt
    keyword = 'exclusiveMinimum'
    message = 'must be greater than {}'


class NumberMultipleOfValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        self.multiple_of = self.parent._read_float('multipleOf', unparsed_keys)
        if self.multiple_of <= 0:
            raise InvalidSchemaException(f"multipleOf must be positive", self)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, (int, float)):
            return []

        multiple = instance / self.multiple_of
        ok = True
        try:
            ok = multiple == int(multiple)
        except OverflowError:
            ok = False
        if ok:
            return [KeywordValidationResult(['multipleOf'])]
        else:
            return [KeywordValidationResult(['multipleOf'], [], f"Must be multiple of {self.multiple_of}")]


class ObjectMinPropertiesValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        self.min_properties = self.parent._read_float('minProperties', unparsed_keys, 0)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, dict):
            return []
        if len(instance.keys()) >= self.min_properties:
            return [KeywordValidationResult(['minProperties'])]
        else:
            return [KeywordValidationResult(['minProperties'], [], f"Must have at least {self.min_properties} properties")]


class ObjectMaxPropertiesValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        self.max_properties = self.parent._read_float('maxProperties', unparsed_keys, float('inf'))

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, dict):
            return []
        if len(instance.keys()) <= self.max_properties:
            return [KeywordValidationResult(['maxProperties'])]
        else:
            return [KeywordValidationResult(['maxProperties'], [], f"Must have at most {self.max_properties} properties")]


class ObjectRequiredValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        required = self.parent._read_list('required', unparsed_keys, [])
        self.required: Set[str] = set()
        for idx, value in enumerate(required):
            sub_pointer = self.parent.pointer + "required" + idx
            if value in self.required:
                raise InvalidSchemaException(f"Duplicate required value {value}", sub_pointer)
            if not isinstance(value, str):
                raise InvalidSchemaException(f"Required value must be a string", sub_pointer)
            self.required.add(value)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, dict):
            return []

        result: List[KeywordValidationResult] = []
        for idx, name in enumerate(self.required):
            if name in instance:
                result.append(KeywordValidationResult(['required', idx]))
            else:
                result.append(KeywordValidationResult(['required', idx], [], f"Property {name} is missing"))
                if config.short_circuit_evaluation:
                    return result

        return result


class ObjectDependentRequiredValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        dependent_required = self.parent._read_dict('dependentRequired', unparsed_keys, {})
        self.dependent_required: Dict[str, Set[str]] = {}
        for key, values in dependent_required.items():
            values_set: Set[str] = set()
            if not isinstance(values, list):
                raise InvalidSchemaException(f"Expected an array", self.parent.pointer + key)
            for idx, value in enumerate(values):
                if not isinstance(value, str):
                    raise InvalidSchemaException(f"Expected a string", self.parent.pointer + key + idx)
                if value in values_set:
                    raise InvalidSchemaException(f"Duplicate entry", self.parent.pointer + key + idx)
                values_set.add(value)
            self.dependent_required[key] = values_set

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, dict):
            return []

        result: List[KeywordValidationResult] = []
        for property, dependent_properties in self.dependent_required.items():
            if property in instance:
                for i in dependent_properties:
                    if i in instance:
                        result.append(KeywordValidationResult(['dependentRequired', property, i]))
                    else:
                        result.append(KeywordValidationResult(['dependentRequired', property, i], [], f"Property {i} is missing"))
                        if config.short_circuit_evaluation:
                            return result
        return result


class ObjectPropertyNamesValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        schema = self.parent._read_any('propertyNames', unparsed_keys)
        self.name_validator = SchemaValidator(schema, parent.pointer + 'propertyNames', parent.root)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, dict):
            return []

        result: List[KeywordValidationResult] = []
        for key in instance.keys():
            sub_result = self.name_validator._invoke(key, config)
            if sub_result.ok:
                # TODO: may result into multiple useless copies this result
                result.append(KeywordValidationResult(['propertyNames'], [sub_result]))
            else:
                result.append(KeywordValidationResult(['propertyNames'], [sub_result], f"Property name {key} is invalid"))
                if config.short_circuit_evaluation:
                    return result

        return result


class ObjectPropertiesValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES

        # Properties
        properties = self.parent._read_dict('properties', unparsed_keys, {})
        self.property_validators: Dict[str, SchemaValidator] = {}
        for name, sub_schema in properties.items():
            self.property_validators[name] = SchemaValidator(sub_schema, self.parent.pointer + name, self.parent.root)

        # Pattern properties
        pattern_properties = self.parent._read_dict('patternProperties', unparsed_keys, {})
        self.pattern_properties: List[Tuple[str, Pattern, SchemaValidator]] = []
        for pattern, sub_schema in pattern_properties.items():
            self.pattern_properties.append((
                pattern,
                re.compile(pattern),
                SchemaValidator(sub_schema, self.parent.pointer + pattern, self.parent.root)
            ))

        # Additional properties
        additional_properties = self.parent._read_any('additionalProperties', unparsed_keys, None)
        if additional_properties is None:
            self.additional_properties_validator: Optional[SchemaValidator] = None
        else:
            self.additional_properties_validator = SchemaValidator(
                additional_properties,
                self.parent.pointer + 'additionalProperties',
                self.parent.root
            )


        # unevaluated properties
        # TODO
        if 'unevaluatedProperties' in parent.schema:
            unevaluated_properties = self.parent._read_any('unevaluatedProperties', unparsed_keys, None)
            self.unevaluated_properties_validator = SchemaValidator(unevaluated_properties, self.parent.pointer + 'unevaluated_properties', self.parent.root)
        else:
            self.unevaluated_properties_validator = None

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, dict):
            return []

        result: List[KeywordValidationResult] = []

        unevaluated_properties = set(instance.keys())

        # Properties
        for name, validator in self.property_validators.items():
            if name in instance:
                unevaluated_properties.remove(name)
                sub_result = validator._invoke(instance[name], config)
                if sub_result.ok:
                    result.append(KeywordValidationResult(['properties', name], [sub_result]))
                else:
                    result.append(KeywordValidationResult(['properties', name], [sub_result], f"Property {name} is invalid"))
                    if config.short_circuit_evaluation:
                        return result

        # Pattern Properties
        for pattern, regex, validator in self.pattern_properties:
            for key, value in instance.items():
                if regex.search(key) is not None:
                    _remove_if_exists(unevaluated_properties, key)
                    sub_result = validator._invoke(value, config)
                    if sub_result.ok:
                        result.append(KeywordValidationResult(['patternProperties', pattern], [sub_result]))
                    else:
                        result.append(KeywordValidationResult(['patternProperties', pattern], [sub_result], f"Property {key} is invalid"))
                        if config.short_circuit_evaluation:
                            return result

        # Additional Properties
        if self.additional_properties_validator:
            for key in unevaluated_properties:
                sub_result = self.additional_properties_validator._invoke(instance[key], config)
                if sub_result.ok:
                    result.append(KeywordValidationResult(['additionalProperties'], [sub_result]))
                else:
                    result.append(KeywordValidationResult(['additionalProperties'], [sub_result], f"Additional property {key} is invalid"))
                    if config.short_circuit_evaluation:
                        return result

        # Unevaluated properties
        if self.unevaluated_properties_validator:
            # TODO: must check not validated keys of sub-schemas, too
            for key in unevaluated_properties:
                sub_result = self.unevaluated_properties_validator._invoke(instance[key], config)
                # TODO: this key is wrong
                if sub_result.ok():
                    result.append(KeywordValidationResult(['unevaluatedProperties'], [sub_result]))
                else:
                    result.append(KeywordValidationResult(['unevaluatedProperties'], [sub_result], f"Unevaluated property {key} is invalid"))
                    if config.short_circuit_evaluation:
                        return result

        return result


class ArrayContainsValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        self.min_contains = self.parent._read_int('minContains', unparsed_keys, None)
        self.max_contains = self.parent._read_int('maxContains', unparsed_keys, None)
        schema = self.parent._read_any('contains', unparsed_keys, None)
        if schema is None:
            self.contains_validator = None
        else:
            self.contains_validator = SchemaValidator(schema, self.parent.pointer + 'contains', self.parent.root)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, list):
            return []

        if self.contains_validator is None:
            return []

        num_matches = 0
        sub_results = []
        for value in instance:
            sub_result = self.contains_validator._invoke(value, config)
            sub_results.append(sub_result)
            if sub_result.ok:
                num_matches += 1
                # TODO: could short circuit, here

        result = []
        if self.min_contains is not None:
            if num_matches < self.min_contains:
                result.append(KeywordValidationResult(['minContains'], sub_results, 'Too few contains instances'))
        else:
            if num_matches == 0:
                result.append(KeywordValidationResult(['contains'], sub_results, 'Element is not found'))

        if self.max_contains is not None:
            if num_matches > self.max_contains:
                result.append(KeywordValidationResult(['maxContains'], sub_results, 'Too many contains instances'))

        return result


class ArrayItemsValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES
        items = self.parent._read_any('items', unparsed_keys, {})
        self.items_validator = SchemaValidator(items, self.parent.pointer + 'items', self.parent.root)
        prefix_items = self.parent._read_list('prefixItems', unparsed_keys, [])
        self.prefix_items_validators = [
            SchemaValidator(prefix_schema, self.parent.pointer + idx, self.parent.root)
            for idx, prefix_schema in enumerate(prefix_items)
        ]

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, list):
            return {}

        result: List[KeywordValidationResult] = []
        num_prefix_items = min(len(instance), len(self.prefix_items_validators))

        # Prefix items
        for idx, prefix_item in enumerate(instance[:num_prefix_items]):
            prefix_item_result = self.prefix_items_validators[idx]._invoke(prefix_item, config)
            if prefix_item_result.ok:
                result.append(KeywordValidationResult(['prefixItems', idx], [prefix_item_result]))
            else:
                result.append(KeywordValidationResult(['prefixItems', idx], [prefix_item_result], 'invalid prefix item'))
                if config.short_circuit_evaluation:
                    return result

        # Items
        for idx, item in enumerate(instance[num_prefix_items:]):
            item_result = self.items_validator._invoke(item, config)
            if item_result.ok:
                result.append(KeywordValidationResult(['items']))
            else:
                result.append(KeywordValidationResult(['items'], [], f'item {idx} is invalid'))
                if config.short_circuit_evaluation:
                    return result

        return result


class ArrayMinItemsValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.min_items = self.parent._read_float('minItems', unparsed_keys, 0)
        self.types = ALL_JSON_TYPES

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, list):
            return []
        if len(instance) < self.min_items:
            return [KeywordValidationResult(['minItems'], [], f"Array is shorter than {self.min_items}")]
        return [KeywordValidationResult(['minItems'])]


class ArrayMaxItemsValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.max_items = self.parent._read_float('maxItems', unparsed_keys, 0)
        self.types = ALL_JSON_TYPES

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, list):
            return []
        if len(instance) > self.max_items:
            return [KeywordValidationResult(['maxItems'], [], f"Array is longer than {self.max_items}")]
        return [KeywordValidationResult(['maxItems'])]


class TypeValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        type_names = self.parent._read_any('type', unparsed_keys)
        if isinstance(type_names, str):
            type_names = [type_names]
        try:
            self.types = set()
            for i in type_names:
                self.types = self.types.union(from_typename(i))
        except TypeException as e:
            raise InvalidSchemaException(str(e), self.pointer)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        instance_types = from_instance(instance)
        if instance_types.isdisjoint(self.types):
            return [KeywordValidationResult(['type'], [], f"Expected {self.types}, got {instance_types}")]
        else:
            return [KeywordValidationResult(['type'])]


class EnumValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.values = self.parent._read_list('enum', unparsed_keys, [])
        self.types = set()
        for value in self.values:
            self.types |= from_instance(value)

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        for i in self.values:
            if values_are_equal(instance, i):
                return [KeywordValidationResult(['enum'])]
        return [KeywordValidationResult(['enum'], [], f"Instance does not match any enum value")]


class AnyValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = ALL_JSON_TYPES

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        return []


class NothingValidator(KeywordsValidator):

    def __init__(self, parent: "SchemaValidator", unparsed_keys: Set[str]):
        super().__init__(parent, unparsed_keys)
        self.types = set()

    def validate(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        return [KeywordValidationResult([], [], f"Schema is always invalid")]


def _remove_if_exists(set: set, key: str):
    if key in set:
        set.remove(key)


class SchemaValidator():
    """
    Validates a whole schema.
    An instance is accepted iff all keyword validators of the schema accept the instance.
    """

    validators_by_key = {
        'not': NotValidator,
        'if': IfThenElseValidator,
        'then': IfThenElseValidator,
        'else': IfThenElseValidator,

        'allOf': AllOfValidator,
        'anyOf': AnyOfValidator,
        'oneOf': OneOfValidator,

        '$ref': ReferenceValidator,

        'prefixItems': ArrayItemsValidator,
        'items': ArrayItemsValidator,
        'minItems': ArrayMinItemsValidator,
        'maxItems': ArrayMaxItemsValidator,
        'minContains': ArrayContainsValidator,
        'maxContains': ArrayContainsValidator,
        'contains': ArrayContainsValidator,

        'const': ConstValidator,

        'pattern': StringPatternValidator,
        'minLength': StringMinLengthValidator,
        'maxLength': StringMaxLengthValidator,
        "format": StringFormatValidator,

        "minimum": NumberMinimumValidator,
        "maximum": NumberMaximumValidator,
        "exclusiveMinimum": NumberExclusiveMinimumValidator,
        "exclusiveMaximum": NumberExclusiveMaximumValidator,
        "multipleOf": NumberMultipleOfValidator,

        'propertyNames': ObjectPropertyNamesValidator,
        'properties': ObjectPropertiesValidator,
        'patternProperties': ObjectPropertiesValidator,
        'additionalProperties': ObjectPropertiesValidator,
        'unevaluatedProperties': ObjectPropertiesValidator,
        'required': ObjectRequiredValidator,
        'dependentRequired': ObjectDependentRequiredValidator,
        'minProperties': ObjectMinPropertiesValidator,
        'maxProperties': ObjectMaxPropertiesValidator,

        'enum': EnumValidator,

        'type': TypeValidator,
    }

    def __init__(self, schema: JsonValue, pointer: JsonPointer, root: "JsonSchemaValidator") -> None:
        self.validators: List[KeywordsValidator] = []
        self.schema = schema
        self.pointer = pointer
        self.root = root
        self.types: JsonTypes = ALL_JSON_TYPES.copy()

        if str(pointer) in self.root.validators_by_pointer:
            raise InvalidSchemaException(f"Duplicate pointer {pointer}", pointer)
        self.root.validators_by_pointer[str(pointer)] = self

        if isinstance(schema, dict):
            unparsed_keys = set(schema.keys())
            if pointer.is_root():
                _remove_if_exists(unparsed_keys, '$schema')
                _remove_if_exists(unparsed_keys, '$defs')
            _remove_if_exists(unparsed_keys, 'deprecated')
            _remove_if_exists(unparsed_keys, '$comment')
            _remove_if_exists(unparsed_keys, 'default')
        else:
            unparsed_keys = set()

        # Create all keyword validators
        while True:
            constructor = self._find_validator(schema, pointer, unparsed_keys)
            kw_validator = constructor(self, unparsed_keys)
            self.validators.append(kw_validator)
            if not unparsed_keys:
                break

        # Collect types
        for i in self.validators:
            self.types &= i.types

    def _find_validator(self, schema: JsonValue, pointer: JsonPointer, unparsed_keys: Set[str]) -> Callable[[dict, JsonPointer, "JsonSchemaValidator", Set[str]], KeywordsValidator]:

        if isinstance(schema, bool):
            if schema:
                return AnyValidator
            else:
                return NothingValidator

        if not isinstance(schema, dict):
            raise InvalidSchemaException(
                f"Expected dict or bool, got {type(schema)}", pointer)

        if len(unparsed_keys) == 0:
            return AnyValidator

        for key, validator in self.validators_by_key.items():
            if key in unparsed_keys:
                return validator

        raise InvalidSchemaException(
            f"Unknown keys {list(schema.keys())}", pointer)

    def _invoke(self, instance: JsonValue, config: ValidationConfig) -> SchemaValidationResult:
        if config.preprocessor:
            instance = config.preprocessor(instance, self)

        kw_results: List[KeywordValidationResult] = []
        for i in self.validators:
            kw_results.extend(i.validate(instance, config))
        
        return SchemaValidationResult(self, kw_results)

    def _read(self, key: str, type_type: any, type_name: str, unparsed_keys: Set[str], default: any) -> any:
        try:
            value = self.schema[key]
        except KeyError:
            if default is _NoDefault:
                raise InvalidSchemaException(f"Missing key {key}", self.pointer)
            return default

        if not isinstance(value, type_type):
            raise InvalidSchemaException(f"Expected {type_name}, got {type(value)}", self.pointer + key)

        unparsed_keys.remove(key)
        return value

    def _read_list(self, key: str, unparsed_keys: Set[str], default: list = _NoDefault) -> list:
        return self._read(key, list, 'list', unparsed_keys, default)

    def _read_dict(self, key: str, unparsed_keys: Set[str], default: dict = _NoDefault) -> dict:
        return self._read(key, dict, 'dict', unparsed_keys, default)

    def _read_string(self, key: str, unparsed_keys: Set[str], default: str = _NoDefault) -> list:
        return self._read(key, str, 'string', unparsed_keys, default)

    def _read_int(self, key: str, unparsed_keys: Set[str], default: int = _NoDefault) -> int:
        v = self._read(key, (float, int), 'int', unparsed_keys, default)
        if isinstance(v, float):
            if v != int(v):
                raise InvalidSchemaException(f"Expected int, got float {v}", self.pointer + key)
            v = int(v)
        return v

    def _read_float(self, key: str, unparsed_keys: Set[str], default: int = _NoDefault) -> float:
        return self._read(key, (float, int), 'float', unparsed_keys, default)

    def _read_bool(self, key: str, unparsed_keys: Set[str], default: bool = _NoDefault) -> bool:
        return self._read(key, bool, 'bool', unparsed_keys, default)

    def _read_any(self, key: str, unparsed_keys: Set[str], default: any = _NoDefault) -> any:
        return self._read(key, object, 'any', unparsed_keys, default)


class JsonSchemaValidator(SchemaValidator):

    def __init__(self, schema: JsonValue, parse_config: Optional[ParseConfig] = None) -> None:
        root_pointer = JsonPointer()
        self.validators_by_pointer: Dict[str, SchemaValidator] = {}
        if parse_config is None:
            self.parse_config = ParseConfig()
        else:
            self.parse_config = parse_config

        if isinstance(schema, dict):
            actual_schema = schema.get('$schema')
            expected_schema = "https://json-schema.org/draft/2020-12/schema"
            if actual_schema != expected_schema:
                raise InvalidSchemaException(f"Unknown schema dialect, expected {expected_schema}")

        super().__init__(schema, root_pointer, self)

    def invoke(self, instance: JsonValue, config: Optional[ValidationConfig] = None) -> SchemaValidationResult:
        if config is None:
            config = ValidationConfig()
        return self._invoke(instance, config)

    def render_coverage(self, file: FileIO):
        file.write("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>Coverage</title>
        </head>
        <body style="white-space: pre-wrap; font-family:monospace;">""")

        def c(pointer) -> Optional[str]:
            try:
                num_valid = self.validators_by_pointer[str(pointer)].num_valid
                num_invalid = self.validators_by_pointer[str(
                    pointer)].num_invalid
            except KeyError:
                return None
            if num_valid == 0 and num_invalid == 0:
                return 'red'
            if num_valid == 0 or num_invalid == 0:
                return 'orange'
            return 'green'

        def d(schema: JsonValue, pointer: JsonPointer, indent=0, prefix=''):
            color = c(pointer)
            if color:
                file.write(f'<span style="color: {color}">')
            if isinstance(schema, dict):
                for key, value in schema.items():
                    file.write('  ' * indent + prefix + key + ':\n')
                    d(value, pointer + key, indent + 1, '  ')
            elif isinstance(schema, list):
                for idx, value in enumerate(schema):
                    d(value, pointer + idx, indent + 1, '- ')
            else:
                file.write('  ' * indent + prefix + str(schema) + '\n')
            if color:
                file.write('</span>')

        d(self.schema, self.pointer)

        file.write("""
        </body>
        </html>""")
