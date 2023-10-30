# JSON Schema Plus

JSON Schema Plus is a python implementation of JSON Schema, draft 2020-12.
It offers various additional features commonly not found in other libraries

## Validation of JSON documents

The core of JSON Schema Plus is the validation of JSON documents, obviously.
This can be done as follows:

```python
from json_schema_plus import parse_schema

schema = {
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
TBD
