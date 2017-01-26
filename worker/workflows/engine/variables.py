#!/usr/bin/env python

"""
    Variables functions for Business Rules
"""

import inspect

from .utils import fn_name_to_pretty_label, validate_parameters
from .operators import (BaseType,
                        NumericType,
                        StringType,
                        BooleanType,
                        SelectType,
                        SelectMultipleType)


class BaseVariables(object):
    """
        Classe that hold a collection of variables to use with the rules
        engine should inherit from this.
    """
    @classmethod
    def get_all_variables(cls):

        methods = inspect.getmembers(cls)
        variables = []

        for meth in methods:
            if getattr(meth[1], 'is_rule_variable', False):
                variables.append({
                    'name': meth[0],
                    'label': meth[1].label,
                    'field_type': meth[1].field_type.name,
                    'options': meth[1].options,
                    'params': meth[1].params
                })
        return variables


def rule_variable(field_type, label=None, options=None, params=None):
    """
        Decorator to make a function into a rule variable
    """
    options = options or []

    def wrapper(func):
        params_ = params
        if isinstance(params, dict):
            params_ = []
            for name, field_type_ in params.items():
                params_.append(dict(
                    label=fn_name_to_pretty_label(name),
                    name=name,
                    fieldType=field_type_)
                )
        validate_parameters(func, params_)
        if not (type(field_type) == type and issubclass(field_type, BaseType)):
            err_msg = '{0} is not instance of BaseType in rule_variable field_type'
            raise AssertionError(err_msg.format(field_type))

        func.field_type = field_type
        func.is_rule_variable = True
        func.label = label or fn_name_to_pretty_label(func.__name__)
        func.options = options
        func.params = params_
        return func
    return wrapper


def numeric_rule_variable(label=None, options=None, params=None):
    return rule_variable(NumericType, label=label, options=options, params=params)


def string_rule_variable(label=None, options=None, params=None):
    return rule_variable(StringType, label=label, options=options, params=params)


def boolean_rule_variable(label=None, options=None, params=None):
    return rule_variable(BooleanType, label=label, options=options, params=params)


def select_rule_variable(label=None, options=None, params=None):
    return rule_variable(SelectType, label=label, options=options, params=params)


def select_multiple_rule_variable(label=None, options=None, params=None):
    return rule_variable(SelectMultipleType, label=label, options=options, params=params)
