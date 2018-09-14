
from .base import EMAIL_VALID_CATEGORIES, EmailServiceException
from ..helpers import get_implementation_class

assert EMAIL_VALID_CATEGORIES
assert EmailServiceException


class EmailService(object):

    instance = None
    base_class_name = 'EmailServiceBase'

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
    def send_email(cls, *args, **kwargs):

        return cls.instance.send_email(*args, **kwargs)

    @classmethod
    def get_emails(cls, *args, **kwargs):

        return cls.instance.get_emails(*args, **kwargs)

    @classmethod
    def is_email_ticket_answer(cls, *args, **kwargs):

        return cls.instance.is_email_ticket_answer(*args, **kwargs)

    @classmethod
    def attach_external_answer(cls, *args, **kwargs):

        return cls.instance.attach_external_answer(*args, **kwargs)

    @classmethod
    def prefetch_email_from_template(cls, *args, **kwargs):

        return cls.instance.prefetch_email_from_template(*args, **kwargs)

    @classmethod
    def close_thread(cls, *args, **kwargs):

        return cls.instance.close_thread(*args, **kwargs)
