from json_schema_tool.types import JsonType, JsonValue
from .types import from_typename, JsonType, from_instance, values_are_equal, JsonTypes, ALL_JSON_TYPES
from .pointer import JsonPointer

from typing import Dict, List, Optional, Set, Callable, Pattern, Tuple
from .exception import InvalidSchemaException, TypeException, JsonPointerException, PreprocessorException

import re
from dataclasses import dataclass, field
import warnings
import operator

import base64


@dataclass
class ValidationConfig:

    preprocessor: Optional[Callable] = None
    short_circuit_evaluation: bool = False
    strict_content_encoding = False


@dataclass
class ParseConfig:

    format_validators: Dict[str, Callable[[str], bool]] = field(default_factory=dict)
    raise_on_unknown_format: bool = True
    raise_on_unknown_keyword: bool = False


class KeywordValidationResult:

    def __init__(self, sub_pointer: List[str], sub_schema_results: Optional[List["SchemaValidationResult"]] = None, error_message: Optional[str] = None):
        self.sub_pointer = sub_pointer
        self.sub_schema_results = sub_schema_results or []
        self.error_message = error_message

    def ok(self) -> bool:
        return self.error_message is None

    def __repr__(self) -> str:
        return "OK" if self.ok() else "Fail!"


class SchemaValidationResult:
    def __init__(self, validator: "SchemaValidator", sub_results: List[KeywordValidationResult]) -> None:
        self.validator = validator
        self.keyword_results = sub_results
        if len(self.keyword_results) == 0:
            self.ok = True
        else:
            self.ok = all([i.ok() for i in self.keyword_results])

    def dump(self, indent=0):
        print("    " * indent + f"{self.validator.pointer}:")
        if self.ok:
            print("    " * indent + "  OK")
        else:
            print("    " * indent + "  Errors:")
            for result in self.keyword_results:
                if result.error_message:
                    print("    " * indent + "  - " + result.error_message)
                    for i in result.sub_schema_results:
                        i.dump(indent+1)


class Globals:

    def __init__(self, schema: any) -> None:
        self.validators_by_pointer: Dict[str, DictSchemaValidator] = {}
        self.schema = schema


class _NoDefault:
    pass


class KeywordsValidator:
    """
    Validates an instance against one or more keywords in a schema
    """

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        self.parent = parent

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        raise NotImplementedError(f"{self}")

    def get_types(self) -> JsonTypes:
        raise NotImplementedError(f"{self}")

    def sub_pointers(self) -> List[List[str]]:
        raise NotImplementedError(f"{self}")

    def sub_schemas(self) -> List["SchemaValidator"]:
        raise NotImplementedError(f"{self}")


class NotValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self._types = None
        n = self.parent._read_any('not', unparsed_keys)
        self.sub_validator = _construct(n, self.parent.pointer + 'not', self.parent.globals, config)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        sub_result = self.sub_validator._validate(instance, config)
        if sub_result.ok:
            return [KeywordValidationResult(['not'], [sub_result], "Sub-schema must not be valid")]
        else:
            return [KeywordValidationResult(['not'], [sub_result])]

    def sub_schemas(self) -> List[List[str]]:
        return [self.sub_validator]

    def sub_pointers(self) -> List[List[str]]:
        return [["not"]]

    def get_types(self) -> JsonTypes:
        if self._types is None:
            self._types = self.sub_validator.get_types()
        return self._types


class IfThenElseValidator(KeywordsValidator):

    def __get_validator(self, kw: str, unparsed_keys: Set[str], config: ParseConfig) -> Optional["DictSchemaValidator"]:
        if kw in self.parent.schema:
            schema = self.parent._read_any(kw, unparsed_keys)
            return _construct(schema, self.parent.pointer + kw, self.parent.globals, config)
        else:
            return None

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self.if_validator = self.__get_validator('if', unparsed_keys, config)
        self.then_validator = self.__get_validator('then', unparsed_keys, config)
        self.else_validator = self.__get_validator('else', unparsed_keys, config)
        self._types = None

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        # This is valid iff:
        # (not(IF) or THEN) and (IF or ELSE)
        # See https://json-schema.org/understanding-json-schema/reference/conditionals.html#implication

        if not self.if_validator:
            return []

        # Shorthand case: IF without THEN and ELSE is always valid
        if self.then_validator is None and self.else_validator is None:
            return [KeywordValidationResult(['if'])]

        if_result = self.if_validator._validate(instance, config)

        if if_result.ok:
            if self.then_validator:
                then_result = self.then_validator._validate(instance, config)
                if then_result.ok:
                    return [KeywordValidationResult(['if'])]
                else:
                    return [KeywordValidationResult(['if'], [if_result, then_result], f"IF is valid but THEN is invalid")]
        else:
            if self.else_validator:
                else_result = self.else_validator._validate(instance, config)
                if else_result.ok:
                    return [KeywordValidationResult(['if'])]
                else:
                    return [KeywordValidationResult(['if'], [if_result, else_result], f"IF is invalid but ELSE is invalid")]

        return [KeywordValidationResult(['if'], [if_result])]

    def sub_schemas(self) -> List["SchemaValidator"]:
        result = []
        if self.if_validator:
            result.append(self.if_validator)
        if self.then_validator:
            result.append(self.then_validator)
        if self.else_validator:
            result.append(self.else_validator)
        return result

    def sub_pointers(self) -> List[List[str]]:
        if self.if_validator:
            return [['if']]
        else:
            return []

    def get_types(self) -> JsonTypes:
        if self._types is None:
            self._types = set()
            if self.then_validator:
                self._types |= self.then_validator.get_types()
            if self.else_validator:
                self._types |= self.else_validator.get_types()
        return self._types


class AggregatingValidator(KeywordsValidator):
    """
    Base class for allOf, anyOf and oneOf validators
    """
    keyword = ''

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        l = self.parent._read_list(self.keyword, unparsed_keys)
        self.sub_validators: List[DictSchemaValidator] = []
        for idx, sub_schema in enumerate(l):
            sv = _construct(sub_schema, self.parent.pointer + self.keyword + idx, self.parent.globals, config)
            self.sub_validators.append(sv)
        if not self.sub_validators:
            raise InvalidSchemaException(f"Must specify at least one sub-schema", self.parent.pointer)

    def sub_pointers(self) -> List[List[str]]:
        return [[self.keyword]]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return self.sub_validators


class AllOfValidator(AggregatingValidator):

    keyword = 'allOf'

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self._types = None

    def get_types(self) -> JsonTypes:
        if self._types is None:
            self._types = ALL_JSON_TYPES.copy()
            for i in self.sub_validators:
                self._types &= i.get_types()
            if not self._types:
                warnings.warn(f"Found allOf, where Sub-schemas do not share a common type: always rejecting ({self.parent.pointer})")
        return self._types

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        sub_results: List[SchemaValidationResult] = []
        ok = True
        for validators in self.sub_validators:
            result = validators._validate(instance, config)
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

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self._types = None

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        sub_results: List[SchemaValidationResult] = []
        ok = False
        for validators in self.sub_validators:
            result = validators._validate(instance, config)
            if result.ok:
                ok = True
                if config.short_circuit_evaluation:
                    break
            sub_results.append(result)
        if ok:
            return [KeywordValidationResult([self.keyword], sub_results)]
        else:
            return [KeywordValidationResult([self.keyword], sub_results, "Does not match at least one sub-schema")]

    def get_types(self) -> JsonTypes:
        if self._types is None:
            self._types = set()
            for sub_validator in self.sub_validators:
                self._types |= sub_validator.get_types()
        return self._types


class OneOfValidator(AggregatingValidator):

    keyword = 'oneOf'

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self._types = None

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        sub_schema_results: List[SchemaValidationResult] = []
        num_ok = 0
        for validators in self.sub_validators:
            result = validators._validate(instance, config)
            sub_schema_results.append(result)
            if result.ok:
                num_ok += 1
        if num_ok == 1:
            return [KeywordValidationResult([self.keyword], sub_schema_results)]
        else:
            return [KeywordValidationResult([self.keyword], sub_schema_results, "Does not match exactly one sub-schema")]

    def get_types(self) -> JsonTypes:
        if self._types is None:
            self._types = set()
            for sub_validator in self.sub_validators:
                self._types |= sub_validator.get_types()
        return self._types


class ReferenceValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self._types = None
        self.ref = self.parent._read_string('$ref', unparsed_keys)
        try:
            pointer = JsonPointer.from_string(self.ref)
        except JsonPointerException as e:
            raise InvalidSchemaException(f"Invalid JSON pointer: {e}")

        try:
            self.ref_validator = parent.globals.validators_by_pointer[str(pointer)]
        except KeyError:
            ref_schema = pointer.lookup(self.parent.globals.schema)
            self.ref_validator = _construct(ref_schema, pointer, self.parent.globals, config)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        ref_result = self.ref_validator._validate(instance, config)
        if ref_result.ok:
            return [KeywordValidationResult(['$ref'], [ref_result])]
        else:
            return [KeywordValidationResult(['$ref'], [ref_result], f"Reference {self.ref} is invalid")]

    def sub_pointers(self) -> List[List[str]]:
        return [["$ref"]]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return [self.ref_validator]

    def get_types(self) -> JsonTypes:
        if self._types is None:
            self._types = self.ref_validator.get_types()
        return self._types


class ConstValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        unparsed_keys.remove('const')
        self.value = parent.schema['const']
        self._types = from_instance(self.value)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if values_are_equal(self.value, instance):
            return [KeywordValidationResult(['const'])]
        else:
            return [KeywordValidationResult(['const'], [], f"{instance} is not {self.value}")]

    def sub_pointers(self) -> List[List[str]]:
        return ['const']

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def get_types(self) -> JsonTypes:
        return self._types


class StringContentValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)

        # content encoding
        self.content_encoding = self.parent._read_string('contentEncoding', unparsed_keys, None)
        if self.content_encoding is not None:
            checkers = {
                'base64': self.check_base64
            }
            try:
                self.content_checker = checkers[self.content_encoding]
            except KeyError:
                raise InvalidSchemaException(f"Unknown content encoding {self.content_encoding}")

        # content media type
        self.content_media_type = self.parent._read_string("contentMediaType", unparsed_keys, None)

        # content schema
        self.content_schema = self.parent._read_any("contentSchema", unparsed_keys, None)

    def check_base64(self, instance: str) -> Optional[str]:
        return base64.b64decode(instance, validate=True)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, str):
            return []

        result = []

        # Content Encoding
        if self.content_encoding is not None:
            try:
                instance = self.content_checker(instance)
                ok = True
            except ValueError:
                ok = not config.strict_content_encoding
            if ok:
                result.append(KeywordValidationResult(['contentEncoding']))
            else:
                result.append(KeywordValidationResult(['contentEncoding'], [], f"Is not encoded as {self.content_encoding}"))
                if config.short_circuit_evaluation:
                    return result

        result.append(KeywordValidationResult(['contentMediaType']))
        result.append(KeywordValidationResult(['contentSchema']))

        return result

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def sub_pointers(self) -> List[List[str]]:
        return [
            ['contentEncoding'],
            ['contentMediaType'],
            ['contentSchema']
        ]

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class StringPatternValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)

        pattern = self.parent._read_string('pattern', unparsed_keys)
        self.pattern: Pattern = re.compile(pattern)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, str):
            return []

        if self.pattern.search(instance) is None:
            return [KeywordValidationResult(['pattern'], [], f"Value does not match pattern")]
        else:
            return [KeywordValidationResult(['pattern'])]

    def sub_pointers(self) -> List[List[str]]:
        return [["pattern"]]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class StringLimitValidator(KeywordsValidator):

    keyword = ''
    operator = None
    message = ''

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self.limit = self.parent._read_float(self.keyword, unparsed_keys)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, str):
            return []

        if self.operator(len(instance), self.limit):
            return [KeywordValidationResult([self.keyword])]
        else:
            return [KeywordValidationResult([self.keyword], [], self.message.format(self.limit))]

    def sub_pointers(self) -> List[List[str]]:
        return [[self.keyword]]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class StringMinLengthValidator(StringLimitValidator):
    keyword = 'minLength'
    operator = operator.ge
    message = "Value is shorter than {}"


class StringMaxLengthValidator(StringLimitValidator):
    keyword = 'maxLength'
    operator = operator.le
    message = "Value is longer than {}"


class StringFormatValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self.format_name = self.parent._read_string('format', unparsed_keys)
        try:
            self.format_validator = config.format_validators[self.format_name]
        except KeyError:
            if config.raise_on_unknown_format:
                raise InvalidSchemaException(f"Unknown format {self.format_name}")
            else:
                self.format_validator = None

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, str):
            return []
        if self.format_validator is None:
            return []
        if self.format_validator(instance):
            return [KeywordValidationResult(['format'])]
        else:
            return [KeywordValidationResult(['format'], [], f'invalid format, should be {self.format_name}')]

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class NumberLimitValidator(KeywordsValidator):

    operator = None
    keyword = ''
    message = ''

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self.limit = self.parent._read_float(self.keyword, unparsed_keys)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, (int, float)):
            return []

        if self.operator(instance, self.limit):
            return [KeywordValidationResult([self.keyword])]
        else:
            return [KeywordValidationResult([self.keyword], [], self.message.format(self.limit))]

    def sub_pointers(self) -> List[List[str]]:
        return [[self.keyword]]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


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

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self.multiple_of = self.parent._read_float('multipleOf', unparsed_keys)
        if self.multiple_of <= 0:
            raise InvalidSchemaException(f"multipleOf must be positive", self)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
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

    def sub_pointers(self) -> List[List[str]]:
        return [['multipleOf']]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class ObjectPropertyLimitValidator(KeywordsValidator):

    keyword = ''
    operator = None
    message = ''

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self.limit = self.parent._read_float(self.keyword, unparsed_keys)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, dict):
            return []
        if self.operator(len(instance.keys()), self.limit):
            return [KeywordValidationResult([self.keyword])]
        else:
            return [KeywordValidationResult([self.keyword], [], self.message.format(self.limit))]

    def sub_pointers(self) -> List[List[str]]:
        return [[self.keyword]]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class ObjectMinPropertiesValidator(ObjectPropertyLimitValidator):
    keyword = 'minProperties'
    operator = operator.ge
    message = "Must have at least {} properties"


class ObjectMaxPropertiesValidator(ObjectPropertyLimitValidator):
    keyword = 'maxProperties'
    operator = operator.le
    message = "Must have at most {} properties"


class ObjectRequiredValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        required = self.parent._read_list('required', unparsed_keys, [])
        self.required: List[str] = []
        for idx, value in enumerate(required):
            sub_pointer = self.parent.pointer + "required" + idx
            if value in self.required:
                raise InvalidSchemaException(f"Duplicate required value {value}", sub_pointer)
            if not isinstance(value, str):
                raise InvalidSchemaException(f"Required value must be a string", sub_pointer)
            self.required.append(value)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
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

    def sub_pointers(self) -> List[List[str]]:
        return [['required', i] for i in range(len(self.required))]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class ObjectDependentRequiredValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
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

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
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

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def sub_pointers(self) -> List[List[str]]:
        result = []
        for property, dependent_properties in self.dependent_required.items():
            result.extend(["dependentRequired", property, i] for i in dependent_properties)
        return result

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class ObjectPropertyNamesValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        schema = self.parent._read_any('propertyNames', unparsed_keys)
        self.name_validator = _construct(schema, parent.pointer + 'propertyNames', parent.globals, config)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, dict):
            return []

        result: List[KeywordValidationResult] = []
        for key in instance.keys():
            sub_result = self.name_validator._validate(key, config)
            if sub_result.ok:
                # TODO: may result into multiple useless copies this result
                result.append(KeywordValidationResult(['propertyNames'], [sub_result]))
            else:
                result.append(KeywordValidationResult(['propertyNames'], [sub_result], f"Property name {key} is invalid"))
                if config.short_circuit_evaluation:
                    return result

        return result

    def sub_pointers(self) -> List[List[str]]:
        return [["propertyNames"]]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return [self.name_validator]

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class ObjectPropertiesValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)

        # Properties
        properties = self.parent._read_dict('properties', unparsed_keys, {})
        self.property_validators: Dict[str, DictSchemaValidator] = {}
        for name, sub_schema in properties.items():
            self.property_validators[name] = _construct(sub_schema, self.parent.pointer + name, self.parent.globals, config)

        # Pattern properties
        pattern_properties = self.parent._read_dict('patternProperties', unparsed_keys, {})
        self.pattern_properties: List[Tuple[str, Pattern, DictSchemaValidator]] = []
        for pattern, sub_schema in pattern_properties.items():
            self.pattern_properties.append((
                pattern,
                re.compile(pattern),
                _construct(sub_schema, self.parent.pointer + pattern, self.parent.globals, config)
            ))

        # Additional properties
        additional_properties = self.parent._read_any('additionalProperties', unparsed_keys, None)
        if additional_properties is None:
            self.additional_properties_validator: Optional[DictSchemaValidator] = None
        else:
            self.additional_properties_validator = _construct(
                additional_properties,
                self.parent.pointer + 'additionalProperties',
                self.parent.globals,
                config
            )

        # unevaluated properties
        # TODO
        if 'unevaluatedProperties' in parent.schema:
            unevaluated_properties = self.parent._read_any('unevaluatedProperties', unparsed_keys, None)
            self.unevaluated_properties_validator = _construct(unevaluated_properties, self.parent.pointer + 'unevaluated_properties', self.parent.globals, config)
        else:
            self.unevaluated_properties_validator = None

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, dict):
            return []

        result: List[KeywordValidationResult] = []

        unevaluated_properties = set(instance.keys())

        # Properties
        for name, validator in self.property_validators.items():
            if name in instance:
                unevaluated_properties.remove(name)
                sub_result = validator._validate(instance[name], config)
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
                    sub_result = validator._validate(value, config)
                    if sub_result.ok:
                        result.append(KeywordValidationResult(['patternProperties', pattern], [sub_result]))
                    else:
                        result.append(KeywordValidationResult(['patternProperties', pattern], [sub_result], f"Property {key} is invalid"))
                        if config.short_circuit_evaluation:
                            return result

        # Additional Properties
        if self.additional_properties_validator:
            for key in unevaluated_properties:
                sub_result = self.additional_properties_validator._validate(instance[key], config)
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
                sub_result = self.unevaluated_properties_validator._validate(instance[key], config)
                if sub_result.ok:
                    result.append(KeywordValidationResult(['unevaluatedProperties'], [sub_result]))
                else:
                    result.append(KeywordValidationResult(['unevaluatedProperties'], [sub_result], f"Unevaluated property {key} is invalid"))
                    if config.short_circuit_evaluation:
                        return result

        return result

    def sub_schemas(self) -> List["SchemaValidator"]:
        result = []
        result += self.property_validators.values()
        result += [i[2] for i in self.pattern_properties]
        if self.additional_properties_validator:
            result += [self.additional_properties_validator]
        if self.unevaluated_properties_validator:
            result += [self.unevaluated_properties_validator]
        return result

    def sub_pointers(self) -> List[List[str]]:
        result = []
        result += [['properties', i] for i in self.property_validators.keys()]
        result += [['patternProperties', i[0]] for i in self.pattern_properties]
        if self.additional_properties_validator:
            result += ['additionalProperties']
        if self.unevaluated_properties_validator:
            result += ['unevaluatedProperties']
        return result

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class ArrayContainsValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self.min_contains = self.parent._read_int('minContains', unparsed_keys, None)
        self.max_contains = self.parent._read_int('maxContains', unparsed_keys, None)
        schema = self.parent._read_any('contains', unparsed_keys, None)
        if schema is None:
            self.contains_validator = None
        else:
            self.contains_validator = _construct(schema, self.parent.pointer + 'contains', self.parent.globals, config)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, list):
            return []

        if self.contains_validator is None:
            return []

        num_matches = 0
        sub_results = []
        for value in instance:
            sub_result = self.contains_validator._validate(value, config)
            sub_results.append(sub_result)
            if sub_result.ok:
                num_matches += 1
                # TODO: could short circuit, here

        result = []
        if self.min_contains is not None:
            if num_matches >= self.min_contains:
                result.append(KeywordValidationResult(['minContains'], sub_results))
            else:
                result.append(KeywordValidationResult(['minContains'], sub_results, 'Too few contains instances'))
        else:
            if num_matches != 0:
                result.append(KeywordValidationResult(['contains'], sub_results))
            else:
                result.append(KeywordValidationResult(['contains'], sub_results, 'Element is not found'))

        if self.max_contains is not None:
            if num_matches > self.max_contains:
                result.append(KeywordValidationResult(['maxContains'], sub_results, 'Too many contains instances'))

        return result

    def sub_pointers(self) -> List[List[str]]:
        result = []
        if self.min_contains is not None:
            result.append(['minContains'])
        if self.max_contains is not None:
            result.append(['maxContains'])
        if self.contains_validator is not None:
            result.append(['contains'])
        return result

    def sub_schemas(self) -> List["SchemaValidator"]:
        if self.contains_validator is not None:
            return [self.contains_validator]
        else:
            return []

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class ArrayItemsValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        items = self.parent._read_any('items', unparsed_keys, None)
        if items is None:
            self.items_validator = None
        else:
            self.items_validator = _construct(items, self.parent.pointer + 'items', self.parent.globals, config)
        prefix_items = self.parent._read_list('prefixItems', unparsed_keys, [])
        self.prefix_items_validators = [
            _construct(prefix_schema, self.parent.pointer + idx, self.parent.globals, config)
            for idx, prefix_schema in enumerate(prefix_items)
        ]

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, list):
            return {}

        result: List[KeywordValidationResult] = []
        num_prefix_items = min(len(instance), len(self.prefix_items_validators))

        # Prefix items
        for idx, prefix_item in enumerate(instance[:num_prefix_items]):
            prefix_item_result = self.prefix_items_validators[idx]._validate(prefix_item, config)
            if prefix_item_result.ok:
                result.append(KeywordValidationResult(['prefixItems', idx], [prefix_item_result]))
            else:
                result.append(KeywordValidationResult(['prefixItems', idx], [prefix_item_result], 'invalid prefix item'))
                if config.short_circuit_evaluation:
                    return result

        # Items
        if self.items_validator:
            for idx, item in enumerate(instance[num_prefix_items:]):
                item_result = self.items_validator._validate(item, config)
                if item_result.ok:
                    result.append(KeywordValidationResult(['items']))
                else:
                    result.append(KeywordValidationResult(['items'], [item_result], f'item {idx} is invalid'))
                    if config.short_circuit_evaluation:
                        return result

        return result

    def sub_schemas(self) -> List["SchemaValidator"]:
        result = []
        if self.items_validator:
            result.append(self.items_validator)
        result.extend(self.prefix_items_validators)
        return result

    def sub_pointers(self) -> List[List[str]]:
        result = []
        result.extend(['prefixItems', idx] for idx, _ in enumerate(self.prefix_items_validators))
        if self.items_validator:
            result.append(['items'])
        return result

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class ArrayItemsLimitValidator(KeywordsValidator):

    keyword = ''
    operator = None
    message = ''

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self.limit = self.parent._read_float(self.keyword, unparsed_keys)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        if not isinstance(instance, list):
            return []
        if self.operator(len(instance), self.limit):
            return [KeywordValidationResult([self.keyword], [], self.message.format(self.limit))]
        return [KeywordValidationResult([self.keyword])]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def sub_pointers(self) -> List[List[str]]:
        return [[self.keyword]]

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES


class ArrayMinItemsValidator(ArrayItemsLimitValidator):
    keyword = 'minItems'
    operator = operator.lt
    message = "Array is shorter than {}"


class ArrayMaxItemsValidator(ArrayItemsLimitValidator):
    keyword = 'maxItems'
    operator = operator.gt
    message = "Array is longer than {}"


class TypeValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        type_names = self.parent._read_any('type', unparsed_keys)
        if isinstance(type_names, str):
            type_names = [type_names]
        try:
            self._types = set()
            for i in type_names:
                self._types = self._types.union(from_typename(i))
        except TypeException as e:
            raise InvalidSchemaException(str(e), self.pointer)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        instance_types = from_instance(instance)
        if instance_types.isdisjoint(self._types):
            return [KeywordValidationResult(['type'], [], f"Expected {self._types}, got {instance_types}")]
        else:
            return [KeywordValidationResult(['type'])]

    def sub_pointers(self) -> List[List[str]]:
        return [['type']]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def get_types(self) -> JsonTypes:
        return self._types


class EnumValidator(KeywordsValidator):

    def __init__(self, parent: "DictSchemaValidator", unparsed_keys: Set[str], config: ParseConfig):
        super().__init__(parent, unparsed_keys, config)
        self.values = self.parent._read_list('enum', unparsed_keys, [])
        self._types = set()
        for value in self.values:
            self._types |= from_instance(value)

    def invoke(self, instance: JsonValue, config: ValidationConfig) -> List[KeywordValidationResult]:
        for i in self.values:
            if values_are_equal(instance, i):
                return [KeywordValidationResult(['enum'])]
        return [KeywordValidationResult(['enum'], [], f"Instance does not match any enum value")]

    def sub_pointers(self) -> List[List[str]]:
        return [["enum"]]

    def sub_schemas(self) -> List["SchemaValidator"]:
        return []

    def get_types(self) -> JsonTypes:
        return self._types


def _remove_if_exists(set: set, key: str):
    if key in set:
        set.remove(key)


class SchemaValidator():
    """
    Base class for all schema validators
    """

    def __init__(self, pointer: JsonPointer, globals: Globals) -> None:
        self.pointer = pointer
        self.globals = globals

    def validate(self, instance: JsonValue, config: Optional[ValidationConfig] = None):
        if config is None:
            config = ValidationConfig()
        return self._validate(instance, config)

    def _validate(self, instance: JsonValue, config: ValidationConfig) -> SchemaValidationResult:
        raise NotImplementedError(f"{self}")

    def get_types(self) -> JsonTypes:
        raise NotImplementedError(f"{self}")


class DictSchemaValidator(SchemaValidator):
    """
    Validates a whole dict schema.
    An instance is accepted iff all keyword validators of the schema accept the instance.
    """

    validators_by_key = [
        ('not', NotValidator),
        ('if', IfThenElseValidator),
        ('then', IfThenElseValidator),
        ('else', IfThenElseValidator),
        ('allOf', AllOfValidator),
        ('anyOf', AnyOfValidator),
        ('oneOf', OneOfValidator),
        ('$ref', ReferenceValidator),
        ('prefixItems', ArrayItemsValidator),
        ('items', ArrayItemsValidator),
        ('minItems', ArrayMinItemsValidator),
        ('maxItems', ArrayMaxItemsValidator),
        ('minContains', ArrayContainsValidator),
        ('maxContains', ArrayContainsValidator),
        ('contains', ArrayContainsValidator),
        ('const', ConstValidator),
        ('pattern', StringPatternValidator),
        ('minLength', StringMinLengthValidator),
        ('maxLength', StringMaxLengthValidator),
        ("format", StringFormatValidator),
        ("contentEncoding", StringContentValidator),
        ("contentMediaType", StringContentValidator),
        ("contentSchema", StringContentValidator),
        ("minimum", NumberMinimumValidator),
        ("maximum", NumberMaximumValidator),
        ("exclusiveMinimum", NumberExclusiveMinimumValidator),
        ("exclusiveMaximum", NumberExclusiveMaximumValidator),
        ("multipleOf", NumberMultipleOfValidator),
        ('propertyNames', ObjectPropertyNamesValidator),
        ('properties', ObjectPropertiesValidator),
        ('patternProperties', ObjectPropertiesValidator),
        ('additionalProperties', ObjectPropertiesValidator),
        ('unevaluatedProperties', ObjectPropertiesValidator),
        ('required', ObjectRequiredValidator),
        ('dependentRequired', ObjectDependentRequiredValidator),
        ('minProperties', ObjectMinPropertiesValidator),
        ('maxProperties', ObjectMaxPropertiesValidator),
        ('enum', EnumValidator),
        ('type', TypeValidator),
    ]

    def __init__(self, schema: JsonValue, pointer: JsonPointer, globals: Globals, config: ParseConfig) -> None:
        super().__init__(pointer, globals)
        self.kw_validators: List[KeywordsValidator] = []
        self.schema = schema
        self._types: Optional[JsonTypes] = None

        if str(pointer) in self.globals.validators_by_pointer:
            raise InvalidSchemaException(f"Duplicate pointer {pointer}", pointer)
        self.globals.validators_by_pointer[str(pointer)] = self

        unparsed_keys = set(schema.keys())
        _remove_if_exists(unparsed_keys, 'deprecated')
        _remove_if_exists(unparsed_keys, '$comment')
        _remove_if_exists(unparsed_keys, 'default')

        # Create all keyword validators
        for key, validator in self.validators_by_key:
            if key in unparsed_keys:
                kw_validator = validator(self, unparsed_keys, config)
                self.kw_validators.append(kw_validator)
        if unparsed_keys and config.raise_on_unknown_keyword:
            raise InvalidSchemaException(f"Unknown keys {list(schema.keys())}", pointer)

    def _validate(self, instance: JsonValue, config: ValidationConfig) -> SchemaValidationResult:
        if config.preprocessor:
            try:
                instance = config.preprocessor(instance, self)
            except PreprocessorException as e:
                return SchemaValidationResult(self, [KeywordValidationResult([], [], str(e))])

        kw_results: List[KeywordValidationResult] = []
        for i in self.kw_validators:
            sub_results = i.invoke(instance, config)
            kw_results.extend(sub_results)
            if config.short_circuit_evaluation and any(not i.ok() for i in sub_results):
                break

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

    def get_types(self) -> JsonTypes:
        if self._types is None:
            self._types: JsonTypes = ALL_JSON_TYPES.copy()
            for i in self.kw_validators:
                self._types &= i.get_types()
        return self._types


class AnyValidator(SchemaValidator):

    def __init__(self, pointer: JsonPointer, globals: Globals) -> None:
        super().__init__(pointer, globals)

    def _validate(self, instance: JsonValue, config: ValidationConfig) -> SchemaValidationResult:
        return SchemaValidationResult(self, [])

    def get_types(self) -> JsonTypes:
        return ALL_JSON_TYPES.copy()


class NothingValidator(SchemaValidator):

    def _validate(self, instance: JsonValue, config: ValidationConfig) -> SchemaValidationResult:
        result = SchemaValidationResult(self, [])
        result.ok = False
        return result

    def get_types(self) -> JsonTypes:
        return set()


def parse_schema(schema: JsonValue, config: Optional[ParseConfig] = None) -> SchemaValidator:
    if config is None:
        config = ParseConfig()

    if isinstance(schema, dict):
        actual_schema = schema.get('$schema')
        expected_schema = "https://json-schema.org/draft/2020-12/schema"
        if actual_schema != expected_schema:
            raise InvalidSchemaException(f"Unknown schema dialect, expected {expected_schema}")
        clean_schema = schema.copy()
        for i in ['$schema', '$defs']:
            if i in clean_schema:
                del clean_schema[i]
    else:
        clean_schema = schema

    return _construct(clean_schema, JsonPointer(), Globals(schema), config)


def _construct(schema: JsonValue, pointer: JsonPointer, globals: Globals, config: ParseConfig) -> SchemaValidator:
    if schema is False:
        return NothingValidator(pointer, globals)
    elif schema is True:
        return AnyValidator(pointer, globals)
    elif isinstance(schema, dict):
        return DictSchemaValidator(schema, pointer, globals, config)
    else:
        raise InvalidSchemaException(f"Schema must be a bool or dict, got {type(schema)}")
