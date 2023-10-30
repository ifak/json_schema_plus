import os
import json
import sys

from unittest import TestCase

from json_schema_plus import schema, exception

script_dir = os.path.dirname(os.path.realpath(__file__))


class SchemaTestSuite(TestCase):

    def test_all(self):

        class Colors:
            GREEN = '\033[92m'
            ORANGE = '\033[93m'
            RED = '\033[91m'
            BOLD = '\033[1m'
            ENDC = '\033[0m'

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
            'contentMediaType',
            'content.json',
            'not.json',
        ]

        root = os.path.join(
            script_dir, 'JSON-Schema-Test-Suite/tests/draft2020-12')
        for file in sorted(os.listdir(root)):
            print(Colors.BOLD + file + Colors.ENDC)
            if file in blacklist:
                print(Colors.ORANGE + "SKIP" + Colors.ENDC + "\n")
                continue
            with open(os.path.join(root, file)) as f:
                test_suites = json.load(f)
            for test_suite in test_suites:
                print(test_suite['description'])
                try:
                    validator = schema.JsonSchemaValidator(test_suite['schema'])
                except exception.InvalidSchemaException as e:
                    print(e)
                    print(Colors.RED + "FAIL (parse)" + Colors.ENDC)
                    raise e
                self.assertIsNotNone(validator.types)
                for test_case in test_suite['tests']:
                    valid = test_case['valid']
                    result = validator.invoke(test_case['data'])
                    sys.stdout.write(" * " + test_case['description'] + ": ")
                    if result.ok != valid:
                        sys.stdout.write(Colors.RED + "FAIL\n" + Colors.ENDC)
                    else:
                        sys.stdout.write(Colors.GREEN + "PASS\n" + Colors.ENDC)
                    sys.stdout.write("\n")
                    self.assertEqual(result.ok, valid)
                    result.dump()
            print()
