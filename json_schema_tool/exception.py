class JsonSchemaPlusException(Exception):
    pass


class TypeException(JsonSchemaPlusException):
    pass


class InvalidSchemaException(JsonSchemaPlusException):
    pass


class JsonPointerException(JsonSchemaPlusException):
    pass


class CoverageException(JsonSchemaPlusException):
    pass


class PreprocessorException(JsonSchemaPlusException):
    pass