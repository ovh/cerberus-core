
from .base import ReputationServiceException
from ..helpers import get_implementation_class

assert ReputationServiceException


class ReputationService(object):

    instance = None
    base_class_name = 'ReputationServiceBase'

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
    def get_ip_rbl_reputations(cls, *args, **kwargs):

        return cls.instance.get_ip_rbl_reputations(*args, **kwargs)

    @classmethod
    def get_ip_external_reputations(cls, *args, **kwargs):

        return cls.instance.get_ip_external_reputations(*args, **kwargs)

    @classmethod
    def get_ip_external_details(cls, *args, **kwargs):

        return cls.instance.get_ip_external_details(*args, **kwargs)

    @classmethod
    def get_url_external_reputations(cls, *args, **kwargs):

        return cls.instance.get_url_external_reputations(*args, **kwargs)

    @classmethod
    def get_ip_internal_reputations(cls, *args, **kwargs):

        return cls.instance.get_ip_internal_reputations(*args, **kwargs)

    @classmethod
    def get_ip_tools(cls, *args, **kwargs):

        return cls.instance.get_ip_tools(*args, **kwargs)
