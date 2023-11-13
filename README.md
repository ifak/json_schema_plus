# JSON Schema Tool

[![Tests](https://github.com/ifak/json_schema_tool/actions/workflows/check.yml/badge.svg)](https://github.com/ifak/json_schema_tool/actions/workflows/check.yml)

JSON Schema Tool is a python implementation of JSON Schema, draft 2020-12.
It offers various additional features commonly not found in other libraries

Obviously, the core of JSON Schema Tool is the validation of JSON documents.
This can be done as follows:

```python
from json_schema_tool import parse_schema

schema = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    'type': 'object',
    'properties': {
        'foo': {
            'type': 'string'
        }
    }
}

validator = parse_schema(schema)

result = validator.validate({"foo": "bar"})
# result.ok == True

result = validator.validate("invalid")
# result.ok == False

```

## Installation

You can install JSON Schema Tool via pip:

```sh
python -m pip install json_schema_tool
```

## Schema Coverage Measurement
You can use coverage to assess the completeness of your test data.
Schema coverage works on the keyword level, i.e., JsonSchema Tool checks, how many constraints have been actually checked during instance validation:

```python
from json_schema_tool import coverage, parse_schema
schema = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    'type': 'object',
    'properties': {
        'foo': {
            'type': 'string'
        }
    }
}

validator = parse_schema(schema)
cov = coverage.SchemaCoverage(validator)

result = validator.validate({})
cov.update(result)
print(cov.coverage())
# 0.3

result = validator.validate({"foo": "bar"})
cov.update(result)
print(cov.coverage())
# 1.0

with open("schema-coverage.html", "w") as f:
    cov.render_coverage(f)
```

## Type Inference
Given a validator, you can use it to query the types of the schema.
This even works for complex and composed schemas:
```python
from json_schema_tool import parse_schema
schema = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    'anyOf': [
        {"type": "object"},
        {"const": "foo"}
    ]
}
validator = parse_schema(schema)
print(validator.get_types())
# {'object', 'string'}
```

## Validation Performance
You can drastically increase validation performance by using short circuit evaluation (SCE).
By using SCE, evaluation terminates as soon as the first error in the JSON instance is found.
For example, an allOf does not visit all sub schemas, if the first sub-schema already fails.
You can activate SCE as follows:

```python
from json_schema_tool import schema

# use parse_schema to build your validator...

config = schema.ValidationConfig(short_circuit_evaluation=True)
result = validator.validate({"foo": "bar"}, config)
```
Please note, that SCE does not work together with coverage measurement.
