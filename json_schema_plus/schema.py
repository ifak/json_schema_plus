from json_schema_plus.pointer import JsonPointer
from json_schema_plus.types import JsonType, JsonValue
from .types import from_typename, JsonType, from_instance, values_are_equal, JsonTypes, ALL_JSON_TYPES
from .pointer import JsonPointer

from typing import Dict, List, Optional, Set, Callable, Pattern, Tuple
from .exception import InvalidSchemaException, TypeException

from io import FileIO
import re
from dataclasses import dataclass, field


@dataclass
class ValidationConfig:

    preprocessor: Optional[Callable] = None


@dataclass
class ParseConfig:

    format_validators: Dict[str, Callable[[str], bool]] = field(
        default_factory=dict)
    raise_on_unknown_format: bool = True


class ValidationError:
    def __init__(self, message: str, validator: "Validator", caused_by: List["ValidationError"] = None) -> None:
        self.message = message
        self.validator = validator
        self.caused_by = caused_by or []

    def dump(self, indent=0):
        print("  " * indent + f"{self.validator.pointer}: {self.message}")
        for i in self.caused_by:
            i.dump(indent+1)


class _NoDefault:
    pass


class Validator:
    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        self.pointer = pointer
        self.schema = schema
        self.root = root
        self.num_valid = 0
        self.num_invalid = 0
        self.types: JsonType = None

    def get_error(self, instance: JsonValue, config: ValidationConfig = ValidationConfig()) -> Optional[ValidationError]:
        error = self._get_error_impl(instance, config)
        if error:
            self.num_invalid += 1
        else:
            self.num_valid += 1
        return error

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        raise NotImplementedError(f"{self}")

    def _construct(self, schema: JsonValue, pointer: JsonPointer) -> "ValidatorCollection":
        return self.root._construct_validator(schema, pointer)

    def _read(self, key: str, type_type: any, type_name: str, unparsed_keys: Set[str], default: any) -> any:
        try:
            value = self.schema[key]
        except KeyError:
            if default is _NoDefault:
                raise InvalidSchemaException(
                    f"Missing key {key}", self.pointer)
            return default

        if not isinstance(value, type_type):
            raise InvalidSchemaException(
                f"Expected {type_name}, got {type(value)}", self.pointer + key)

        unparsed_keys.remove(key)
        return value

    def _read_list(self, key: str, unparsed_keys: Set[str], default: list = _NoDefault) -> list:
        return self._read(key, list, 'list', unparsed_keys, default)

    def _read_dict(self, key: str, unparsed_keys: Set[str], default: dict = _NoDefault) -> dict:
        return self._read(key, dict, 'dict', unparsed_keys, default)

    def _read_string(self, key: str, unparsed_keys: Set[str], default: str = _NoDefault) -> list:
        return self._read(key, str, 'string', unparsed_keys, default)

    def _read_int(self, key: str, unparsed_keys: Set[str], default: int = _NoDefault) -> int:
        return self._read(key, int, 'int', unparsed_keys, default)

    def _read_float(self, key: str, unparsed_keys: Set[str], default: int = _NoDefault) -> float:
        return self._read(key, (float, int), 'float', unparsed_keys, default)

    def _read_bool(self, key: str, unparsed_keys: Set[str], default: bool = _NoDefault) -> bool:
        return self._read(key, bool, 'bool', unparsed_keys, default)

    def _read_any(self, key: str, unparsed_keys: Set[str], default: bool = _NoDefault) -> any:
        return self._read(key, object, 'any', unparsed_keys, default)

    def _resolve_types(self) -> JsonTypes:
        assert self.types is not None
        return self.types


class NotValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        n = self._read_any('not', unparsed_keys)
        self.validators = self._construct(n, pointer + 'not')

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        errors = self.validators.invoke(instance, config)
        if not errors:
            return ValidationError("Sub-schema must not be valid", self)
        else:
            return None

    def _resolve_types(self) -> JsonTypes:
        if not self.types:
            self.types = self.validators.get_types()
        return self.types


class IfThenElseValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        if 'if' in schema:
            self.if_validator = self._construct(
                self._read_any('if', unparsed_keys),
                pointer + 'if',
            )
        else:
            self.if_validator = None

        if 'then' in schema:
            self.then_validators = self._construct(
                self._read_any('then', unparsed_keys),
                pointer + 'then',
            )
        else:
            self.then_validators = None

        if 'else' in schema:
            self.else_validators = self._construct(
                self._read_any('else', unparsed_keys),
                pointer + 'else',
            )
        else:
            self.else_validators = None

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        # This is valid iff:
        # (not(IF) or THEN) and (IF or ELSE)
        # See https://json-schema.org/understanding-json-schema/reference/conditionals.html#implication

        if not self.if_validator:
            return None

        if self.then_validators:
            then_errors = self.then_validators.invoke(instance, config)
        else:
            then_errors = []

        if self.else_validators:
            else_errors = self.else_validators.invoke(instance, config)
        else:
            else_errors = []

        # Shorthand case: THEN and IF are valid
        if not then_errors and not else_errors:
            return None

        if_errors = self.if_validator.invoke(instance, config)

        if then_errors:
            if not if_errors:
                return ValidationError(f"IF is valid but THEN is invalid", self, then_errors)

        if else_errors:
            if if_errors:
                return ValidationError(f"IF is invalid but ELSE is invalid", self, else_errors)

        return None

    def _resolve_types(self) -> JsonTypes:
        if not self.types:
            self.types = set()
            if self.then_validators:
                self.types |= self.then_validators.get_types()
            if self.else_validators:
                self.types |= self.else_validators.get_types()
        return self.types


class AggregatingValidator(Validator):

    keyword = ''

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        l = self._read_list(self.keyword, unparsed_keys)
        self.sub_validators: List[ValidatorCollection] = []
        for idx, sub_schema in enumerate(l):
            self.sub_validators.append(self._construct(
                sub_schema, pointer + self.keyword + idx))
        if not self.sub_validators:
            raise InvalidSchemaException(
                f"Must specify at least one sub-schema", pointer)


class AllOfValidator(AggregatingValidator):

    keyword = 'allOf'

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        sub_errors: List[ValidationError] = []
        for validators in self.sub_validators:
            errors = validators.invoke(instance, config)
            if errors:
                sub_errors.extend(errors)
        if sub_errors:
            return ValidationError("Does not match all sub-schemas", self, sub_errors)
        return None

    def _resolve_types(self) -> JsonTypes:
        if not self.types:
            self.types = ALL_JSON_TYPES.copy()
            for i in self.sub_validators:
                self.types &= i.get_types()
            if not self.types:
                raise InvalidSchemaException(
                    f"Sub-schemas do not share a common type, always rejecting", self.pointer)

        return self.types


class AnyOfValidator(AggregatingValidator):

    keyword = 'anyOf'

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        sub_errors: List[ValidationError] = []
        for validators in self.sub_validators:
            errors = validators.invoke(instance, config)
            if errors:
                sub_errors.extend(errors)
            else:
                return None
        return ValidationError("Does not match at least one sub-schema", self, sub_errors)

    def _resolve_types(self) -> JsonTypes:
        if not self.types:
            self.types = set()
            for sub_validator in self.sub_validators:
                self.types |= sub_validator.get_types()
        return self.types


class OneOfValidator(AggregatingValidator):

    keyword = 'oneOf'

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        sub_errors: List[ValidationError] = []
        for validators in self.sub_validators:
            errors = validators.invoke(instance, config)
            if errors:
                sub_errors.extend(errors)
        if len(sub_errors) != len(self.sub_validators) - 1:
            return ValidationError("Does not match exactly one sub-schema", self, sub_errors)
        return None

    def _resolve_types(self) -> JsonTypes:
        if not self.types:
            self.types = set()
            for sub_validator in self.sub_validators:
                self.types |= sub_validator.get_types()
        return self.types


class ReferenceValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        self.ref = self._read_string('$ref', unparsed_keys)
        self.resolved_ref: Optional[ValidatorCollection] = None

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        errors = self.resolved_ref.invoke(instance, config)
        if errors:
            return ValidationError(f"Reference {self.ref} is invalid", self, errors)
        return None

    def _resolve_types(self) -> JsonTypes:
        if not self.types:
            self.types = self.resolved_ref.get_types()
        return self.types


class ConstValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        unparsed_keys.remove('const')
        self.value = schema['const']

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        if values_are_equal(self.value, instance):
            return None
        return ValidationError(f"{instance} is not {self.value}", self)

    def _resolve_types(self) -> JsonTypes:
        if not self.types:
            self.types = from_instance(self.value)
        return self.types


class StringValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        self.types = ALL_JSON_TYPES

        pattern = self._read_string('pattern', unparsed_keys,  None)
        if pattern:
            self.pattern: Optional[Pattern] = re.compile(pattern)
        else:
            self.pattern = None
        self.encoding = self._read_string(
            'contentEncoding', unparsed_keys, None)
        self.min_length = self._read_float('minLength', unparsed_keys, 0)
        self.max_length = self._read_float(
            'maxLength', unparsed_keys, float('inf'))
        self.format_validator = None
        if 'format' in self.schema:
            f = self._read_string('format', unparsed_keys)
            try:
                self.format_validator = self.root.parse_config.format_validators[f]
            except KeyError:
                if self.root.parse_config.raise_on_unknown_format:
                    raise InvalidSchemaException(f"Unknown format {f}")

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        if not isinstance(instance, str):
            return None
        if len(instance) < self.min_length:
            return ValidationError(f"Value is shorter than {self.min_length}", self)
        if len(instance) > self.max_length:
            return ValidationError(f"Value is longer than {self.max_length}", self)
        if self.pattern and self.pattern.search(instance) is None:
            return ValidationError(f"Value does not match pattern", self)
        # TODO: encoding
        if self.format_validator is not None:
            if not self.format_validator(instance):
                return ValidationError(f"Invalid format", self)
        return None

    def _resolve_types(self) -> JsonTypes:
        return self.types


class NumberValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        self.types = ALL_JSON_TYPES

        self.maximum = self._read_float(
            'maximum', unparsed_keys, float('+inf'))
        self.minimum = self._read_float(
            'minimum', unparsed_keys, float('-inf'))
        self.maximum_exclusive = self._read_float(
            'exclusiveMaximum', unparsed_keys, float('+inf'))
        self.minimum_exclusive = self._read_float(
            'exclusiveMinimum', unparsed_keys, float('-inf'))
        self.multiple_of = self._read_float('multipleOf', unparsed_keys, None)
        if self.multiple_of is not None and self.multiple_of <= 0:
            raise InvalidSchemaException(f"multipleOf must be positive", self)

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        if not isinstance(instance, (int, float)):
            return None

        if instance < self.minimum:
            return ValidationError(f"Must be equal or greater than {self.minimum}", self)
        if instance <= self.minimum_exclusive:
            return ValidationError(f"Must be greater than {self.minimum}", self)
        if instance > self.maximum:
            return ValidationError(f"Must be equal or less than {self.maximum}", self)
        if instance >= self.maximum_exclusive:
            return ValidationError(f"Must be less than {self.maximum_exclusive}", self)
        if self.multiple_of:
            multiple = instance / self.multiple_of
            ok = True
            try:
                ok = multiple == int(multiple)
            except OverflowError:
                ok = False
            if not ok:
                return ValidationError(f"Must be multiple of {self.multiple_of}", self)
        return None

    def _resolve_types(self) -> JsonTypes:
        return self.types


class ObjectValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        self.types = ALL_JSON_TYPES

        # Min/max Properties
        self.min_properties = self._read_float(
            'minProperties', unparsed_keys, 0)
        self.max_properties = self._read_float(
            'maxProperties', unparsed_keys, float('inf'))

        # Properties
        properties = self._read_dict('properties', unparsed_keys, {})
        self.property_validators: Dict[str, ValidatorCollection] = {}
        for name, sub_schema in properties.items():
            self.property_validators[name] = (self._construct(
                sub_schema, pointer + name)
            )

        # Pattern properties
        pattern_properties = self._read_dict(
            'patternProperties', unparsed_keys, {})
        self.pattern_properties: List[Tuple[Pattern, ValidatorCollection]] = []
        for pattern, sub_schema in pattern_properties.items():
            self.pattern_properties.append((
                re.compile(pattern),
                self._construct(sub_schema, pointer + pattern)
            ))

        # Required
        required = self._read_list('required', unparsed_keys, [])
        self.required: Set[str] = set()
        for idx, value in enumerate(required):
            sub_pointer = pointer + "required" + idx
            if value in self.required:
                raise InvalidSchemaException(
                    f"Duplicate required value {name}", sub_pointer)
            if not isinstance(value, str):
                raise InvalidSchemaException(
                    f"Required value must be a string", sub_pointer)
            self.required.add(value)

        # Dependent required
        dependent_required = self._read_dict('dependentRequired', unparsed_keys, {})
        self.dependent_required: Dict[str, Set[str]] = {}
        for key, values in dependent_required.items():
            values_set: Set[str] = set()
            if not isinstance(values, list):
                raise InvalidSchemaException(
                    f"Expected an array", pointer + key)
            for idx, value in enumerate(values):
                if not isinstance(value, str):
                    raise InvalidSchemaException(
                        f"Expected a string", pointer + key + idx)
                if value in values_set:
                    raise InvalidSchemaException(
                        f"Duplicate entry", pointer + key + idx)
                values_set.add(value)
            self.dependent_required[key] = values_set

        # Additional properties
        additional_properties = self._read_any(
            'additionalProperties', unparsed_keys, None)
        if additional_properties is None:
            self.additional_properties_validator: Optional[ValidatorCollection] = None
        else:
            self.additional_properties_validator = self._construct(
                additional_properties, self.pointer + 'additionalProperties')

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        if not isinstance(instance, dict):
            return None

        if len(instance.keys()) < self.min_properties:
            return ValidationError(f"Must have at least {self.min_properties} properties", self)

        if len(instance.keys()) > self.max_properties:
            return ValidationError(f"Must have at most {self.max_properties} properties", self)

        not_validated_keys = set(instance.keys())

        # Properties
        for name, validators in self.property_validators.items():
            if name in instance:
                not_validated_keys.remove(name)
                errors = validators.invoke(instance[name], config)
                if errors:
                    return ValidationError(f"Property {name} is invalid", self, errors)

        # Pattern Properties
        for pattern, validators in self.pattern_properties:
            for key, value in instance.items():
                if pattern.search(key) is not None:
                    _remove_if_exists(not_validated_keys, key)
                    errors = validators.invoke(value, config)
                    if errors:
                        return ValidationError(f"Property {key} is invalid", self, errors)

        # Additional Properties
        if self.additional_properties_validator:
            for key, value in instance.items():
                if key in not_validated_keys:
                    errors = self.additional_properties_validator.invoke(
                        value, config)
                    if errors:
                        return ValidationError(f"Property {key} is invalid", self, errors)

        # Required
        for name in self.required:
            if name not in instance:
                return ValidationError(f"Property {name} is missing", self)

        # Dependent required
        for property, dependent_properties in self.dependent_required.items():
            if property in instance:
                for i in dependent_properties:
                    if i not in instance:
                        return ValidationError(f"Property {i} is missing", self)

        return None

    def _resolve_types(self) -> JsonTypes:
        return self.types


class ArrayItemsValidator(Validator):
    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        self.types = ALL_JSON_TYPES
        self.min_items = self._read_float('minItems', unparsed_keys, 0)
        self.max_items = self._read_float(
            'maxItems', unparsed_keys, float('inf'))
        items = self._read_any('items', unparsed_keys, {})
        self.items_validator = self._construct(
            items, pointer + 'items')

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        if not isinstance(instance, list):
            return None

        if len(instance) < self.min_items:
            return ValidationError(f"Array is shorter than {self.min_items}", self)
        if len(instance) > self.max_items:
            return ValidationError(f"Array is longer than {self.max_items}", self)
        caused_by: List[ValidationError] = []
        for item in instance:
            errors = self.items_validator.invoke(item, config)
            if errors:
                caused_by.extend(errors)
        if caused_by:
            return ValidationError(f"Invalid items", self, caused_by)
        return None


class ArrayMinItemsValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        self.min_items = self._read_float('minItems', unparsed_keys, 0)
        self.types = ALL_JSON_TYPES

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        if not isinstance(instance, list):
            return None
        if len(instance) < self.min_items:
            return ValidationError(f"Array is shorter than {self.min_items}", self)
        return None

    def _resolve_types(self) -> JsonTypes:
        return self.types


class ArrayMaxItemsValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        self.max_items = self._read_float('maxItems', unparsed_keys, 0)
        self.types = ALL_JSON_TYPES

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        if not isinstance(instance, list):
            return None
        if len(instance) > self.max_items:
            return ValidationError(f"Array is longer than {self.max_items}", self)
        return None

    def _resolve_types(self) -> JsonTypes:
        return self.types


class TypeValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        type_names = self._read_any('type', unparsed_keys)
        if isinstance(type_names, str):
            type_names = [type_names]
        try:
            self.types = set()
            for i in type_names:
                self.types = self.types.union(from_typename(i))
        except TypeException as e:
            raise InvalidSchemaException(str(e), self.pointer)

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        instance_types = from_instance(instance)
        if instance_types.isdisjoint(self.types):
            return ValidationError(f"Expected {self.types}, got {instance_types}", self)
        return None

    def _resolve_types(self) -> JsonTypes:
        return self.types


class EnumValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        self.values = self._read_list('enum', unparsed_keys, [])

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        for i in self.values:
            if values_are_equal(instance, i):
                return None
        return ValidationError(f"Instance does not match any enum value", self)

    def _resolve_types(self) -> JsonTypes:
        if not self.types:
            self.types = set()
            for value in self.values:
                self.types |= from_instance(value)
        return self.types


class AnyValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        self.types = ALL_JSON_TYPES

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        return None


class NothingValidator(Validator):

    def __init__(self, schema: dict, pointer: JsonPointer, root: "JsonSchemaValidator", unparsed_keys: Set[str]):
        super().__init__(schema, pointer, root, unparsed_keys)
        self.types = set()

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        return ValidationError(f"Schema is always invalid", self)


def _remove_if_exists(set: set, key: str):
    if key in set:
        set.remove(key)


class ValidatorCollection():

    def __init__(self, validators: List[Validator] = None) -> None:
        self.validators = validators or []

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> Optional[List[ValidationError]]:
        if config.preprocessor:
            instance = config.preprocessor(instance, self)

        result = []
        for i in self.validators:
            error = i.get_error(instance, config)
            if error:
                result.append(error)
        if result:
            return result
        return None

    def get_types(self) -> JsonTypes:
        result = ALL_JSON_TYPES.copy()
        for i in self.validators:
            result &= i._resolve_types()
        return result


class JsonSchemaValidator(Validator):

    validators_by_key = {
        'not': NotValidator,
        'if': IfThenElseValidator,
        'then': IfThenElseValidator,
        'else': IfThenElseValidator,

        'allOf': AllOfValidator,
        'anyOf': AnyOfValidator,
        'oneOf': OneOfValidator,

        '$ref': ReferenceValidator,

        'items': ArrayItemsValidator,
        'minItems': ArrayMinItemsValidator,
        'maxItems': ArrayMaxItemsValidator,

        'const': ConstValidator,

        'pattern': StringValidator,
        'minLength': StringValidator,
        'maxLength': StringValidator,
        'contentEncoding': StringValidator,
        "format": StringValidator,

        "minimum": NumberValidator,
        "maximum": NumberValidator,
        "exclusiveMinimum": NumberValidator,
        "exclusiveMaximum": NumberValidator,
        "multipleOf": NumberValidator,

        'properties': ObjectValidator,
        'patternProperties': ObjectValidator,
        'additionalProperties': ObjectValidator,
        'required': ObjectValidator,
        'dependentRequired': ObjectValidator,
        'minProperties': ObjectValidator,
        'maxProperties': ObjectValidator,

        'enum': EnumValidator,

        'type': TypeValidator,
    }

    def __init__(self, schema: JsonValue, parse_config: Optional[ParseConfig] = None) -> None:
        root_pointer = JsonPointer([])
        super().__init__(schema, root_pointer, self, set())
        if parse_config is None:
            self.parse_config = ParseConfig()
        else:
            self.parse_config = parse_config

        self.validators_by_pointer: Dict[str, ValidatorCollection] = {}

        # Parse root schema
        self.validators = self._construct_validator(schema, root_pointer)

        if isinstance(schema, dict):
            actual_schema = schema.get('$schema')
            expected_schema = "https://json-schema.org/draft/2020-12/schema"
            if actual_schema != expected_schema:
                raise InvalidSchemaException(
                    f"Unknown schema dialect, expected {expected_schema}")
            defs = schema.get('$defs', {})
            if not isinstance(defs, dict):
                raise InvalidSchemaException(f"Expected a dict", self.pointer)

            # Parse definitions
            definitions_pointer = root_pointer + '$defs'
            for key, sub_schema in defs.items():
                self._construct_validator(
                    sub_schema, definitions_pointer + key)

        # Resolve $refs
        for pointer, collection in self.validators_by_pointer.items():
            for validator in collection.validators:
                if not isinstance(validator, ReferenceValidator):
                    continue
                try:
                    validator.resolved_ref = self.validators_by_pointer[validator.ref]
                except KeyError:
                    raise InvalidSchemaException(
                        f"Invalid reference {validator.ref}", pointer)

        self._resolve_types()

    def _get_error_impl(self, instance: JsonValue, config: ValidationConfig) -> Optional[ValidationError]:
        errors = self.validators.invoke(instance, config)
        if errors:
            return ValidationError(f"Schema is invalid", self, errors)
        return None

    def _find_validator(self, schema: JsonValue, pointer: JsonPointer, unparsed_keys: Set[str]) -> Callable[[dict, JsonPointer, "JsonSchemaValidator", Set[str]], Validator]:

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

    def _construct_validator(self, schema: JsonValue, pointer: JsonPointer) -> ValidatorCollection:
        if str(pointer) in self.validators_by_pointer:
            raise InvalidSchemaException(
                f"Duplicate pointer {pointer}", pointer)

        if isinstance(schema, dict):
            unparsed_keys = set(schema.keys())
            if pointer.is_root():
                _remove_if_exists(unparsed_keys, '$schema')
                _remove_if_exists(unparsed_keys, '$defs')
            _remove_if_exists(unparsed_keys, 'deprecated')
        else:
            unparsed_keys = set()

        result = ValidatorCollection()
        while True:
            constructor = self._find_validator(schema, pointer, unparsed_keys)
            result.validators.append(
                constructor(schema, pointer, self, unparsed_keys))
            if not unparsed_keys:
                break

        self.validators_by_pointer[str(pointer)] = result
        return result

    def _resolve_types(self) -> JsonTypes:
        if not self.types:
            self.types = self.validators.get_types()
        return self.types

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
