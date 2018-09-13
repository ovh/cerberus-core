
from functools import wraps
from importlib import import_module
from inspect import getmro
from voluptuous import Invalid, MultipleInvalid


class InvalidFormatError(Exception):
    """ Exception raised when schema is not respected

        .. py:class:: InvalidFormatError
    """
    def __init__(self, message):
        super(InvalidFormatError, self).__init__(message)


class SchemaNotFound(Exception):
    """ Exception raised when schema is not found

        .. py:class:: SchemaNotFound
    """
    def __init__(self, message):
        super(SchemaNotFound, self).__init__(message)


def validate_implementation_response(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            schema = args[0].schemas[func.__name__]
            response = func(*args, **kwargs)
            if response:
                schema(response)
            return response
        except (AttributeError, KeyError, TypeError, ValueError):
            raise SchemaNotFound(
                "Schema not found for '{}'".format(func.__name__)
            )
        except (Invalid, MultipleInvalid) as ex:
            raise InvalidFormatError(
                'Given data is not compliant to {} schema: {}'.format(
                    func.__name__, str(ex)
                )
            )
    return wrapper


class WrongImplementationException(Exception):
    """
        Exception raised when provided implementation
        does not inherit of our interface.

        .. py:class:: WrongImplementationException
    """
    def __init__(self, message):
        super(WrongImplementationException, self).__init__(message)


def get_implementation_class(base_name, impl_name):

    module, cls = impl_name.rsplit('.', 1)
    module = import_module(module)
    impl_class = getattr(module, cls)

    if getmro(impl_class)[-2].__name__ != base_name:
        raise WrongImplementationException(
            'class {} does not inherit {}'.format(
                impl_name, base_name
            )
        )

    return impl_class
