from json_schema_tool.types import from_instance, JsonType, values_are_equal, from_typename, ALL_JSON_TYPES
from unittest import TestCase
from json_schema_tool.exception import TypeException

class FromInstanceTest(TestCase):

    def test_string(self):
        t = from_instance('foo')
        self.assertTrue(JsonType.STRING in t)
        t = from_instance(None)
        self.assertFalse(JsonType.STRING in t)

    def test_integer(self):
        t = from_instance(1)
        self.assertTrue(JsonType.INTEGER in t)
        # each integer is also a number
        self.assertTrue(JsonType.NUMBER in t)
        t = from_instance('foo')
        self.assertTrue(JsonType.INTEGER not in t)
        self.assertTrue(JsonType.NUMBER not in t)

    def test_number(self):
        t = from_instance(3.14)
        self.assertTrue(JsonType.NUMBER in t)
        # not every number is an integer...
        self.assertTrue(JsonType.INTEGER not in t)

        t = from_instance(3.0)
        self.assertTrue(JsonType.NUMBER in t)
        # ...only those without decimal places
        self.assertTrue(JsonType.INTEGER in t)

        t = from_instance("3.14")
        self.assertTrue(JsonType.NUMBER not in t)
        self.assertTrue(JsonType.INTEGER not in t)

    def test_bool(self):
        t = from_instance(True)
        self.assertTrue(JsonType.BOOLEAN in t)
        t = from_instance(False)
        self.assertTrue(JsonType.BOOLEAN in t)
        t = from_instance(None)
        self.assertTrue(JsonType.BOOLEAN not in t)

    def test_null(self):
        t = from_instance(None)
        self.assertTrue(JsonType.NULL in t)
        t = from_instance('null')
        self.assertTrue(JsonType.NULL not in t)

    def test_object(self):
        t = from_instance({})
        self.assertTrue(JsonType.OBJECT in t)
        t = from_instance('null')
        self.assertTrue(JsonType.OBJECT not in t)

    def test_array(self):
        t = from_instance([])
        self.assertTrue(JsonType.ARRAY in t)
        t = from_instance({})
        self.assertTrue(JsonType.ARRAY not in t)

    def test_all(self):
        t = from_instance("foo")
        self.assertFalse(ALL_JSON_TYPES.isdisjoint(t))
        t = from_instance(1)
        self.assertFalse(ALL_JSON_TYPES.isdisjoint(t))
        t = from_instance(3.14)
        self.assertFalse(ALL_JSON_TYPES.isdisjoint(t))
        t = from_instance([])
        self.assertFalse(ALL_JSON_TYPES.isdisjoint(t))
        t = from_instance({})
        self.assertFalse(ALL_JSON_TYPES.isdisjoint(t))
        t = from_instance(False)
        self.assertFalse(ALL_JSON_TYPES.isdisjoint(t))
        t = from_instance(None)
        self.assertFalse(ALL_JSON_TYPES.isdisjoint(t))

    def test_invalid(self):
        with self.assertRaises(TypeException):
            from_instance(set())

class FromTypenameTest(TestCase):

    def test_valid(self):
        t = from_typename('object')
        self.assertEqual({JsonType.OBJECT}, t)

        t = from_typename('integer')
        self.assertEqual({JsonType.INTEGER}, t)

        t = from_typename('array')
        self.assertEqual({JsonType.ARRAY}, t)

        t = from_typename('boolean')
        self.assertEqual({JsonType.BOOLEAN}, t)

        t = from_typename('number')
        self.assertEqual({JsonType.NUMBER}, t)

        t = from_typename('string')
        self.assertEqual({JsonType.STRING}, t)

    def test_invalid(self):
        with self.assertRaises(TypeException):
            from_typename('foo')
        with self.assertRaises(TypeException):
            from_typename(12)

class JsonValuesEqual(TestCase):

    def test_false(self):
        self.assertTrue(values_are_equal(False, False))
        self.assertFalse(values_are_equal(False, True))
        self.assertFalse(values_are_equal(False, 0))
        self.assertFalse(values_are_equal(False, 1))
        self.assertFalse(values_are_equal(False, '1'))
        self.assertFalse(values_are_equal(False, '0'))
        self.assertFalse(values_are_equal(False, ['0']))
        self.assertFalse(values_are_equal(False, []))
        self.assertFalse(values_are_equal(False, {'a': 0}))
        self.assertFalse(values_are_equal(False, {}))

    def test_true(self):
        self.assertTrue(values_are_equal(True, True))
        self.assertFalse(values_are_equal(True, False))
        self.assertFalse(values_are_equal(True, 0))
        self.assertFalse(values_are_equal(True, 1))
        self.assertFalse(values_are_equal(True, '1'))
        self.assertFalse(values_are_equal(True, '0'))
        self.assertFalse(values_are_equal(True, ['0']))
        self.assertFalse(values_are_equal(True, []))
        self.assertFalse(values_are_equal(True, {'a': 0}))
        self.assertFalse(values_are_equal(True, {}))

    def test_null(self):
        self.assertTrue(values_are_equal(None, None))
        self.assertFalse(values_are_equal(None, True))
        self.assertFalse(values_are_equal(None, False))
        self.assertFalse(values_are_equal(None, 0))
        self.assertFalse(values_are_equal(None, 1))
        self.assertFalse(values_are_equal(None, '1'))
        self.assertFalse(values_are_equal(None, '0'))
        self.assertFalse(values_are_equal(None, ['0']))
        self.assertFalse(values_are_equal(None, []))
        self.assertFalse(values_are_equal(None, {'a': 0}))
        self.assertFalse(values_are_equal(None, {}))

    def test_string(self):
        self.assertTrue(values_are_equal('a', 'a'))
        self.assertFalse(values_are_equal('', True))
        self.assertFalse(values_are_equal('', False))
        self.assertFalse(values_are_equal('0', 0))
        self.assertFalse(values_are_equal('1', 1))
        self.assertFalse(values_are_equal('0', ['0']))
        self.assertFalse(values_are_equal('0', []))
        self.assertFalse(values_are_equal('foo', {'a': 0}))
        self.assertFalse(values_are_equal('bar', {}))
        self.assertFalse(values_are_equal('bar', None))

    def test_list(self):
        self.assertTrue(values_are_equal(['a'], ['a']))
        self.assertFalse(values_are_equal(['a'], True))
        self.assertFalse(values_are_equal([''], False))
        self.assertFalse(values_are_equal([None], None))
        self.assertFalse(values_are_equal(['a', 'b'], ['b', 'a']))
        self.assertFalse(values_are_equal(['a'], ['b', 'a']))

    def test_dict(self):
        self.assertTrue(values_are_equal({}, {}))
        self.assertTrue(values_are_equal(
            {'foo': 'bar'}, {'foo': 'bar'}))
        self.assertTrue(values_are_equal(
            {'foo': ['bar']}, {'foo': ['bar']}))
        self.assertFalse(values_are_equal({'foo': ['bar']}, {}))
        self.assertFalse(values_are_equal({'foo': ['bar']}, ['bar']))
        self.assertFalse(values_are_equal({}, None))
        self.assertFalse(values_are_equal({}, False))
        self.assertFalse(values_are_equal({}, 0))
        self.assertFalse(values_are_equal({'a': 1, 'b': 2}, {'a': 1}))
        self.assertFalse(values_are_equal({'b': 2}, {'a': 1, 'b': 2}))
        self.assertFalse(values_are_equal({'b': 2}, {'a': 2}))

    def test_number(self):
        self.assertTrue(values_are_equal(1, 1))
        self.assertTrue(values_are_equal(1, 1.0))
        self.assertFalse(values_are_equal(0, False))
        self.assertTrue(values_are_equal(1.0, 1))
        self.assertFalse(values_are_equal(2, '2'))
        self.assertFalse(values_are_equal(2, float('inf')))
        self.assertFalse(values_are_equal(2, [2]))
        self.assertFalse(values_are_equal(2, {}))
        self.assertFalse(values_are_equal(0, True))
        self.assertFalse(values_are_equal(1, False))
