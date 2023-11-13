import os
import json

from unittest import TestCase

from json_schema_tool import parse_schema, coverage, exception, schema


script_dir = os.path.dirname(os.path.realpath(__file__))


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
