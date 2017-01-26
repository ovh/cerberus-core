#!/usr/bin/env python

"""
    Actions functions for Business Rules
"""

import inspect

from .utils import fn_name_to_pretty_label, validate_parameters


class BaseActions(object):
    """
        Classe that hold a collection of actions to use with the rules
        engine should inherit from this.
    """
    @classmethod
    def get_all_actions(cls):

        methods = inspect.getmembers(cls)
        actions = []

        for meth in methods:
            if getattr(meth[1], 'is_rule_action', False):
                actions.append({
                    'name': meth[0],
                    'label': meth[1].label,
                    'params': meth[1].params
                })

        return actions


def rule_action(label=None, params=None):
    """ Decorator to make a function into a rule action
    """
    def wrapper(func):
        params_ = params
        if isinstance(params, dict):
            params_ = []
            for name, field_type in params.items():
                params_.append(dict(
                    label=fn_name_to_pretty_label(name),
                    name=name,
                    fieldType=field_type
                ))

        validate_parameters(func, params_)
        func.is_rule_action = True
        func.label = label or fn_name_to_pretty_label(func.__name__)
        func.params = params_
        return func
    return wrapper
