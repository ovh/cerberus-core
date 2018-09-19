
from .base import StorageServiceException
from ..helpers import get_implementation_class

assert StorageServiceException


class StorageService(object):

    instance = None
    base_class_name = "StorageServiceBase"

    @classmethod
    def set_up(cls, app):

        if app.config["IMPLEMENTATIONS"].get(cls.base_class_name):
            impl = app.config["IMPLEMENTATIONS"][cls.base_class_name]["class"]
            impl = get_implementation_class(cls.base_class_name, impl)
            cls.instance = impl(
                app.config["IMPLEMENTATIONS"][cls.base_class_name]["config"],
                logger=app.logger,
            )
            app.logger.info("{} successfully initialized".format(cls.base_class_name))

    @classmethod
    def is_implemented(cls):

        return bool(cls.instance)

    @classmethod
    def read(cls, *args, **kwargs):
        """
            Read an existing object.

            :param str object_name: Unique object name to be read
            :rtype: raw
            :return:  Content of the object
            :raises `cerberus.services.storage.base.StorageServiceException`
        """
        return cls.instance.read(*args, **kwargs)

    @classmethod
    def write(cls, *args, **kwargs):
        """
            Write a new object.

            :param str object_name: Unique object name to be pushed
            :param raw data: Associated data (might be binary content)
            :rtype: bool
            :return: `True` if everything went ok, `False` otherwise
            :raises `cerberus.services.storage.base.StorageServiceException`
        """
        return cls.instance.write(*args, **kwargs)

    @classmethod
    def delete(cls, *args, **kwargs):
        """
            Triggered when an object must be removed.

            :param str object_name: Unique object name that must be removed
            :raises `cerberus.services.storage.base.StorageServiceException`
        """
        return cls.instance.delete(*args, **kwargs)
