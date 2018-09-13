
from voluptuous import Any, Schema

from .base import DefendantClass, CRMServiceException, ServiceClass
from ..helpers import (get_implementation_class,
                       validate_implementation_response)

assert CRMServiceException


class CRMService(object):

    instance = None
    base_class_name = 'CRMServiceBase'

    schemas = {
        'get_services_from_items': Schema([
            {
                'defendant': DefendantClass,
                'service': ServiceClass,
                'items': {
                    'ips': set,
                    'urls': set,
                    'fqdn': set,
                },
            }
        ], required=True),
        'get_customer_infos': Schema(DefendantClass, required=True),
        'get_service_infos': Schema(ServiceClass, required=True),
        'get_customer_services': Schema([
            {
                'zone': Any(str, unicode),
                'services': [{
                    'componentType': Any(str, unicode),
                    'creationDate': int,
                    'expirationDate': int,
                    'name': Any(str, unicode),
                    'reference': Any(str, unicode),
                    'state': Any(str, unicode),
                }]
            }
        ], required=True)
    }

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
    @validate_implementation_response
    def get_services_from_items(cls, *args, **kwargs):

        return cls.instance.get_services_from_items(*args, **kwargs)

    @classmethod
    @validate_implementation_response
    def get_customer_infos(cls, *args, **kwargs):

        return cls.instance.get_customer_infos(*args, **kwargs)

    @classmethod
    @validate_implementation_response
    def get_service_infos(cls, *args, **kwargs):

        return cls.instance.get_service_infos(*args, **kwargs)

    @classmethod
    def get_customer_revenue(cls, *args, **kwargs):

        return cls.instance.get_customer_revenue(*args, **kwargs)

    @classmethod
    @validate_implementation_response
    def get_customer_services(cls, *args, **kwargs):

        return cls.instance.get_customer_services(*args, **kwargs)
