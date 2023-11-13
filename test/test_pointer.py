from json_schema_tool.pointer import JsonPointer
from json_schema_tool.exception import JsonSchemaToolException

from unittest import TestCase


class TestPointer(TestCase):

    def test_add(self):
        p = JsonPointer()
        self.assertEqual(str(p), '#/')
        p += 12
        self.assertEqual(str(p), '#/12')
        p += 'hello'
        self.assertEqual(str(p), '#/12/hello')
        with self.assertRaises(JsonSchemaToolException):
            p += None
