
from .base import KPIServiceException
from ..helpers import get_implementation_class

assert KPIServiceException


class KPIService(object):

    instance = None
    base_class_name = 'KPIServiceBase'

    @classmethod
    def set_up(cls, app):

        if app.config['IMPLEMENTATIONS'].get(cls.base_class_name):
            impl = app.config['IMPLEMENTATIONS'][cls.base_class_name]['class']
            impl = get_implementation_class(cls.base_class_name, impl)
            cls.instance = impl(
                app.config['IMPLEMENTATIONS'][cls.base_class_name]['config'],
                logger=app.logger
            )
            app.logger.info(
                '{} successfully initialized'.format(cls.base_class_name)
            )

    @classmethod
    def is_implemented(cls):
        return bool(cls.instance)

    @classmethod
    def new_ticket(cls, *args, **kwargs):
        cls.instance.new_ticket(*args, **kwargs)

    @classmethod
    def new_ticket_assign(cls, *args, **kwargs):
        cls.instance.new_ticket_assign(*args, **kwargs)

    @classmethod
    def close_ticket(cls, *args, **kwargs):
        cls.instance.close_ticket(*args, **kwargs)

    @classmethod
    def new_report(cls, *args, **kwargs):
        cls.instance.new_report(*args, **kwargs)
