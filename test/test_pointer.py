from json_schema_plus.pointer import JsonPointer
from json_schema_plus.exception import JsonSchemaPlusException

from unittest import TestCase


class TestPointer(TestCase):

    def test_add(self):
        p = JsonPointer()
        self.assertEqual(str(p), '#/')
        p += 12
        self.assertEqual(str(p), '#/12')
        p += 'hello'
        self.assertEqual(str(p), '#/12/hello')
        with self.assertRaises(JsonSchemaPlusException):
            p += None
