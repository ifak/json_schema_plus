import os
import json

from unittest import TestCase

from json_schema_tool import parse_schema, coverage, exception, schema


script_dir = os.path.dirname(os.path.realpath(__file__))


class TestParse(TestCase):

    def test_invalid_type(self):
        with self.assertRaises(exception.InvalidSchemaException):
            parse_schema([])
        with self.assertRaises(exception.InvalidSchemaException):
            parse_schema(None)
        with self.assertRaises(exception.InvalidSchemaException):
            parse_schema(12)
        with self.assertRaises(exception.InvalidSchemaException):
            parse_schema({'anyOf': [12]})


class TestDiscriminator(TestCase):

    def test_invalid_schema(self):
        # not an object
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'discriminator': False
        }
        with self.assertRaises(exception.InvalidSchemaException):
            parse_schema(schema)

        # missing propertyName
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'discriminator': {}
        }
        with self.assertRaises(exception.InvalidSchemaException):
            parse_schema(schema)

        # propertyName not a string
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'discriminator': {
                'propertyName': False
            }
        }
        with self.assertRaises(exception.InvalidSchemaException):
            parse_schema(schema)

        # missing anyOf / oneOf
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'discriminator': {
                'propertyName': 'type'
            }
        }
        with self.assertRaises(exception.InvalidSchemaException):
            parse_schema(schema)

        # cannot have anyOf and oneOf
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'anyOf': [{}],
            'oneOf': [{}],
            'discriminator': {
                'propertyName': 'type'
            }
        }
        with self.assertRaises(exception.InvalidSchemaException):
            parse_schema(schema)

        # All entries need to be references
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'anyOf': [
                {'type': 'string'}
            ],
            'discriminator': {
                'propertyName': 'type'
            }
        }
        with self.assertRaises(exception.InvalidSchemaException):
            parse_schema(schema)

        # OK
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'anyOf': [{'$ref': '#/$defs/Test'}],
            'discriminator': {
                'propertyName': 'type'
            },
            '$defs': {
                'Test': {}
            }
        }
        parse_schema(schema)

    def test_invalid_discriminator_value(self):
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'oneOf': [
                {'$ref': '#/$defs/Dog'},
            ],
            '$defs': {
                'Dog': {
                    'properties': {'sound': {'const': 'woof'}}
                }
            },
            'discriminator': {
                'propertyName': 'type'
            }
        }
        validator = parse_schema(schema)
        result = validator.validate({})
        self.assertFalse(result.ok)
        result = validator.validate({'type': False})
        self.assertFalse(result.ok)

    def test_simple(self):
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'oneOf': [
                {'$ref': '#/$defs/Cat'},
                {'$ref': '#/$defs/Dog'},
            ],
            '$defs': {
                'Cat': {
                    'properties': {'sound': {'const': 'meow'}}
                },
                'Dog': {
                    'properties': {'sound': {'const': 'woof'}}
                }
            },
            'discriminator': {
                'propertyName': 'type'
            }
        }

        validator = parse_schema(schema)

        result = validator.validate({
            'type': 'Cat',
            'sound': 'meow',
        })
        self.assertEqual(result.ok, True)

        result = validator.validate({
            'type': 'Dog',
            'sound': 'woof',
        })
        self.assertEqual(result.ok, True)

        result = validator.validate({
            'type': 'Dog',
            'sound': 'meow',
        })
        self.assertEqual(result.ok, False)

        result = validator.validate({
            'type': 'Sheep',  # does not exist
            'sound': 'meow',
        })
        self.assertEqual(result.ok, False)

    def test_multiple_inheritance(self):
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            '$defs': {
                'Animal': {
                    'oneOf': [
                        {'$ref': '#/$defs/Cat'},
                        {'$ref': '#/$defs/Dog'},
                    ]
                },
                'Cat': {
                    'properties': {'sound': {'const': 'meow'}}
                },
                'Dog': {
                    'properties': {'sound': {'const': 'woof'}}
                },
                'Human': {
                    'oneOf': [
                        {'$ref': '#/$defs/Child'},
                        {'$ref': '#/$defs/Adult'},
                    ]
                },
                'Child': {
                    'properties': {'sound': {'const': 'hi'}}
                },
                'Adult': {
                    'properties': {'sound': {'const': 'welcome'}}
                },
            },
            'oneOf': [
                {'$ref': '#/$defs/Animal'},
                {'$ref': '#/$defs/Human'},
            ],
            'discriminator': {
                'propertyName': 'type'
            }
        }
        validator = parse_schema(schema)

        # invalid type
        result = validator.validate({'type': 'Foo'})
        self.assertFalse(result.ok)

        # invalid property value
        result = validator.validate({'type': 'Child', 'sound': 'welcome'})
        self.assertFalse(result.ok)

        # Ok
        result = validator.validate({'type': 'Child', 'sound': 'hi'})
        self.assertTrue(result.ok)

    def test_duplicate_suffix(self):
        schema = {
            '$schema': 'https://json-schema.org/draft/2020-12/schema',
            'oneOf': [
                {'$ref': '#/$defs/CatCat'},
                {'$ref': '#/$defs/Cat'},
            ],
            '$defs': {
                'Cat': {
                    'properties': {'sound': {'const': 'meow'}}
                },
                'CatCat': {
                    'properties': {'sound': {'const': 'meow-meow'}}
                }
            },
            'discriminator': {
                'propertyName': 'type'
            }
        }

        validator = parse_schema(schema)

        result = validator.validate({'type': 'Cat', 'sound': 'meow'})
        self.assertTrue(result.ok)
        result = validator.validate({'type': 'CatCat', 'sound': 'meow'})
        self.assertFalse(result.ok)
        result = validator.validate({'type': 'Cat', 'sound': 'meow-meow'})
        self.assertFalse(result.ok)
        result = validator.validate({'type': 'CatCat', 'sound': 'meow-meow'})
        self.assertTrue(result.ok)


class SchemaTestSuite(TestCase):

    blacklist = [
        'optional',
        'anchor.json',
        'ref.json',
        'refRemote.json',
        'defs.json',
        'format.json',
        'id.json',
        'vocabulary.json',
        'unevaluatedProperties.json',
        'unevaluatedItems.json',
        'unknownKeyword.json',
        'uniqueItems.json',
        'dynamicRef.json',
        'dependentSchemas.json',
        'not.json',
    ]

    def test_all(self):

        cov_blacklist = [
            "ignore then without if",
            "ignore else without if",
            "maxContains without contains is ignored",
            "minContains without contains is ignored",
            "required default validation",
            "required with empty array"
        ]
        root = os.path.join(script_dir, 'JSON-Schema-Test-Suite/tests/draft2020-12')
        output = False
        for file in sorted(os.listdir(root)):
            if output:
                print(file)
            if file in self.blacklist:
                if output:
                    print("SKIP")
                continue
            with open(os.path.join(root, file)) as f:
                test_suites = json.load(f)
            for test_suite in test_suites:
                if output:
                    print(test_suite['description'])
                validator = parse_schema(test_suite['schema'])
                self.assertIsNotNone(validator.get_types())

                try:
                    cov = coverage.SchemaCoverage(validator)
                except exception.CoverageException:
                    cov = None
                if cov:
                    self.assertEqual(cov.coverage(), 0)
                for test_case in test_suite['tests']:
                    valid = test_case['valid']
                    result = validator.validate(test_case['data'])
                    if cov:
                        cov.update(result)
                    if output:
                        print(" * " + test_case['description'])
                    self.assertEqual(result.ok, valid)
                    if output:
                        result.dump()
                if cov:
                    if test_suite['description'] in cov_blacklist:
                        continue
                    self.assertGreater(cov.coverage(), .0)

    def test_shortcut(self):
        config = schema.ValidationConfig(short_circuit_evaluation=True)
        root = os.path.join(script_dir, 'JSON-Schema-Test-Suite/tests/draft2020-12')
        output = False
        for file in sorted(os.listdir(root)):
            if output:
                print(file)
            if file in self.blacklist:
                if output:
                    print("SKIP")
                continue
            with open(os.path.join(root, file)) as f:
                test_suites = json.load(f)
            for test_suite in test_suites:
                if output:
                    print(test_suite['description'])
                validator = parse_schema(test_suite['schema'])
                self.assertIsNotNone(validator.get_types())

                for test_case in test_suite['tests']:
                    valid = test_case['valid']
                    result = validator.validate(test_case['data'], config)
                    if output:
                        print(" * " + test_case['description'])
                    self.assertEqual(result.ok, valid)
                    if output:
                        result.dump()
