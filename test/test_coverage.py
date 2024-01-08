from json_schema_tool import coverage, parse_schema
from unittest import TestCase


class CoverageTest(TestCase):

    def test_recursion(self):
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'type': 'array',
            'items': {
                "$ref": "#"
            }
        }
        validator = parse_schema(schema)
        coverage.SchemaCoverage(validator)

    def test_object(self):
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

        result = validator.validate({"foo": "bar"})
        cov.update(result)
        self.assertLessEqual(cov.coverage(), 1.0)

        result = validator.validate("12")
        cov.update(result)
        self.assertLessEqual(cov.coverage(), 1.0)

        result = validator.validate({"foo": 12})
        cov.update(result)
        self.assertEqual(cov.coverage(), 1.0)

        with open("schema-coverage.html", "w") as f:
            cov.render_coverage(f)
