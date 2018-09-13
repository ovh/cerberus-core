
from .base import ActionServiceException
from ..helpers import get_implementation_class

assert ActionServiceException


class ActionService(object):

    instance = None
    base_class_name = 'ActionServiceBase'

    @classmethod
    def set_up(cls, app):

        if app.config['IMPLEMENTATIONS'].get(cls.base_class_name):
            impl = app.config['IMPLEMENTATIONS'][cls.base_class_name]['class']
            impl = get_implementation_class(cls.base_class_name, impl)
            cls.instance = impl(
                app.config['IMPLEMENTATIONS'][cls.base_class_name]['config'],
                logger=app.logger
            )
            app.logger.debug(
                '{} successfully initialized'.format(cls.base_class_name)
            )

    @classmethod
    def is_implemented(cls):

        return bool(cls.instance)

    @classmethod
    def close_service(cls, *args, **kwargs):

        return cls.instance.close_service(*args, **kwargs)

    @classmethod
    def close_all_services(cls, *args, **kwargs):

        return cls.instance.close_all_services(*args, **kwargs)

    @classmethod
    def close_defendant(cls, *args, **kwargs):

        return cls.instance.close_defendant(*args, **kwargs)

    @classmethod
    def apply_action_on_service(cls, *args, **kwargs):

        return cls.instance.apply_action_on_service(*args, **kwargs)

    @classmethod
    def list_actions_for_ticket(cls, *args, **kwargs):

        return cls.instance.list_actions_for_ticket(*args, **kwargs)
