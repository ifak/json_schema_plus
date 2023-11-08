# JSON Schema Plus

JSON Schema Plus is a python implementation of JSON Schema, draft 2020-12.
It offers various additional features commonly not found in other libraries

## Validation of JSON documents

The core of JSON Schema Plus is the validation of JSON documents, obviously.
This can be done as follows:

```python
from json_schema_plus import parse_schema

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

## Type inference
TBD

## Schema coverage measurement
You can use coverage to assess the completeness of your test data.
Schema coverage works on the keyword level, i.e., JsconSchemaPlus checks, how many constraints have been actually checked during instance validation:

```python
from json_schema_plus import coverage, parse_schema
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
