from io import FileIO
from typing import Set, Optional, Dict
from .pointer import JsonPointer
from .schema import SchemaValidator, SchemaValidationResult, DictSchemaValidator, KeywordsValidator
from .types import JsonValue
from .exception import CoverageException


class KwValidatorCoverage:
    def __init__(self) -> None:
        self.num_valid = 0
        self.num_invalid = 0


def _collect(validator: SchemaValidator, kw_validators: Dict[str, KeywordsValidator], visited: set):
    if id(validator) in visited:
        return
    visited.add(id(validator))

    if isinstance(validator, DictSchemaValidator):
        for kw_validator in validator.kw_validators:
            for sub_pointer in kw_validator.sub_pointers():
                pointer = validator.pointer + sub_pointer
                kw_validators[str(pointer)] = KwValidatorCoverage()
            for sub_schema in kw_validator.sub_schemas():
                _collect(sub_schema, kw_validators, visited)


class SchemaCoverage:

    def __init__(self, validator: SchemaValidator) -> None:
        self.validator = validator
        self.kw_validators: Dict[str, KwValidatorCoverage] = {}
        visited = set()
        _collect(validator, self.kw_validators, visited)
        if not self.kw_validators:
            raise CoverageException("Cannot measure coverage: schema has no keywords")

    def update(self, result: SchemaValidationResult):
        for kw_result in result.keyword_results:
            pointer = result.validator.pointer + kw_result.sub_pointer
            str_pointer = str(pointer)
            if result.ok:
                self.kw_validators[str_pointer].num_valid += 1
            else:
                self.kw_validators[str_pointer].num_invalid += 1
            for sub_schema_result in kw_result.sub_schema_results:
                self.update(sub_schema_result)

    def coverage(self) -> float:
        c = 0
        for i in self.kw_validators.values():
            if i.num_valid or i.num_invalid:
                c += 1
        return c / len(self.kw_validators)

    def reset(self):
        for leaf_coverage in self.kw_validators.values():
            leaf_coverage.num_valid = 0
            leaf_coverage.num_invalid = 0

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
                num_valid = self.kw_validators[str(pointer)].num_valid
                num_invalid = self.kw_validators[str(pointer)].num_invalid
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

        d(self.validator.schema, JsonPointer())

        file.write("""
        </body>
        </html>""")
