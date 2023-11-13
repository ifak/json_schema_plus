class JsonSchemaToolException(Exception):
    pass


class TypeException(JsonSchemaToolException):
    pass


class InvalidSchemaException(JsonSchemaToolException):
    pass


class JsonPointerException(JsonSchemaToolException):
    pass


class CoverageException(JsonSchemaToolException):
    pass


class PreprocessorException(JsonSchemaToolException):
    pass
