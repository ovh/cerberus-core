
from .base import SearchServiceException
from ..helpers import get_implementation_class

assert SearchServiceException


class SearchService(object):

    instance = None
    base_class_name = "SearchServiceBase"

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
    def index_email(cls, *args, **kwargs):

        return cls.instance.index_email(*args, **kwargs)

    @classmethod
    def search_reports(cls, *args, **kwargs):

        return cls.instance.search_reports(*args, **kwargs)
