
import inspect
import json

from importlib import import_module
from ..engine.variables import BaseVariables
from ...utils import cache


class Variables(BaseVariables):

    @classmethod
    def set_up(cls, config):

        cls.methods = set()

        for clss in config:

            module, _cls = clss.rsplit('.', 1)
            module = import_module(module)
            _cls = getattr(module, _cls)

            if inspect.getmro(_cls)[-2].__name__ != 'BaseVariables':
                raise AssertionError(
                    'class {} does not inherit {}'.format(_cls, 'BaseVariables')
                )

            for name, _ in inspect.getmembers(_cls, predicate=inspect.ismethod):
                if not name.startswith('_') and name != 'get_all_variables':
                    if name in cls.methods:
                        raise AttributeError(
                            "Conflicting '{}' variable".format(name)
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


class EmailReplyVariables(Variables):

    classes = []


class CDNRequestVariables(Variables):

    classes = []
    redis_queue = 'cdnrequest:{}:request'

    @classmethod
    @cache.redis_lock('cdnrequest:lock')
    def get_requested_domain(cls, ticket_id, provider):

        entries = cache.RedisHandler.ldump(
            cls.redis_queue.format(provider)
        )
        for entry in entries:
            entry = json.loads(entry)
            if int(entry['request_ticket_id']) == int(ticket_id):
                return entry['domain']

    @classmethod
    @cache.redis_lock('cdnrequest:lock')
    def is_existing_request(cls, ticket_id, provider):
        """
            Check if the answered ticket is in the request cache
        """
        entries = cache.RedisHandler.ldump(
            cls.redis_queue.format(provider)
        )

        for entry in entries:
            entry = json.loads(entry)
            if int(entry['request_ticket_id']) == int(ticket_id):
                return True

        return False


class ReportVariables(Variables):

    classes = []
