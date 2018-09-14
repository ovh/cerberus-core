
import inspect

from importlib import import_module
from ..engine.actions import BaseActions


class Actions(BaseActions):

    @classmethod
    def set_up(cls, config):

        cls.methods = set()

        for clss in config:

            module, _cls = clss.rsplit('.', 1)
            module = import_module(module)
            _cls = getattr(module, _cls)

            if inspect.getmro(_cls)[-2].__name__ != 'BaseActions':
                raise AssertionError(
                    'class {} does not inherit {}'.format(_cls, 'BaseActions')
                )

            for name, _ in inspect.getmembers(_cls, predicate=inspect.ismethod):
                if not name.startswith('_') and name != 'get_all_actions':
                    if name in cls.methods:
                        raise AttributeError(
                            "Conflicting '{}' actions".format(name)
                        )
                    cls.methods.add(name)

            cls.classes.append(_cls)

    def __init__(self, *args, **kwargs):

        self._instances = [i(*args, **kwargs) for i in self.classes]

    def __getattr__(self, attr):

        for instance in self._instances:
            if hasattr(instance, attr):
                return getattr(instance, attr)

        raise AttributeError("'{}' is not a valid attribute".format(attr))


class EmailReplyActions(Actions):

    classes = []


class CDNRequestActions(Actions):

    classes = []


class ReportActions(Actions):

    classes = []
