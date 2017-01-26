#!/usr/bin/env python

"""
    Utils for Business Rules
"""

import inspect
from decimal import Decimal, Inexact, Context

from . import fields


def fn_name_to_pretty_label(name):
    return ' '.join([w.title() for w in name.split('_')])


def export_rule_data(variables, actions):
    """
        export_rule_data is used to export all information about the
        variables, actions, and operators to the client. This will return a
        dictionary with three keys:

        - variables: a list of all available variables along with their label, type and options
        - actions: a list of all actions along with their label and params
        - variable_type_operators: a dictionary of all field_types -> list of available operators
    """
    from . import operators
    actions_data = actions.get_all_actions()
    variables_data = variables.get_all_variables()
    variable_type_operators = {}
    for variable_class in inspect.getmembers(operators, lambda x: getattr(x, 'export_in_rule_data', False)):
        variable_type = variable_class[1]  # getmembers returns (name, value)
        variable_type_operators[variable_type.name] = variable_type.get_all_operators()

    return {"variables": variables_data,
            "actions": actions_data,
            "variable_type_operators": variable_type_operators}


def float_to_decimal(f):
    """
    Convert a floating point number to a Decimal with
    no loss of information. Intended for Python 2.6 where
    casting float to Decimal does not work.
    """
    n, d = f.as_integer_ratio()
    numerator, denominator = Decimal(n), Decimal(d)
    ctx = Context(prec=60)
    result = ctx.divide(numerator, denominator)
    while ctx.flags[Inexact]:
        ctx.flags[Inexact] = False
        ctx.prec *= 2
        result = ctx.divide(numerator, denominator)
    return result


def validate_parameters(func, params):
    """ Verifies that the parameters specified are actual parameters for the
    function `func`, and that the field types are FIELD_* types in fields.
    """
    if params is not None:
        # Verify field name is valid
        valid_fields = [getattr(fields, f) for f in dir(fields) \
                if f.startswith("FIELD_")]
        for param in params:
            param_name, field_type = param['name'], param['fieldType']
            if param_name not in func.__code__.co_varnames:
                raise AssertionError("Unknown parameter name {0} specified for"\
                        " action {1}".format(
                        param_name, func.__name__))

            if field_type not in valid_fields:
                raise AssertionError("Unknown field type {0} specified for"\
                        " action {1} param {2}".format(
                        field_type, func.__name__, param_name))
