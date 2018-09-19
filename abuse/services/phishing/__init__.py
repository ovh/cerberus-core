
from voluptuous import Any, Optional, Schema

from .base import PhishingServiceException, PingResponse
from ..helpers import get_implementation_class, validate_implementation_response

assert PhishingServiceException
assert PingResponse


class PhishingService(object):

    instance = None
    base_class_name = "PhishingServiceBase"

    schemas = {
        "ping_url": Schema(PingResponse, required=True),
        "is_screenshot_viewed": Schema(
            {
                "viewed": bool,
                "views": [{"ip": unicode, "userAgent": unicode, "timestamp": int}],
            },
            required=True,
        ),
        "get_screenshots": Schema(
            [
                {
                    "timestamp": int,
                    "location": unicode,
                    "screenshotId": unicode,
                    Optional("phishingGrade"): Any(None, float),
                    Optional("phishingGradeDetails"): {
                        "category": Any(None, unicode, str),
                        "grade": Any(None, float),
                        "comment": Any(None, unicode, str),
                    },
                    "score": int,
                    "response": {
                        "directAccess": {
                            "statusCode": int,
                            "headers": unicode,
                            "state": unicode,
                        },
                        "proxyAccess": {
                            Optional("proxyAddr"): Any(None, unicode),
                            Optional("statusCode"): Any(None, int),
                            Optional("headers"): Any(None, unicode),
                            Optional("state"): Any(None, unicode),
                        },
                    },
                }
            ],
            required=True,
        ),
        "get_http_headers": Schema(
            {"url": Any(str, unicode), "headers": Any(str, unicode)}, required=True
        ),
    }

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
    @validate_implementation_response
    def ping_url(cls, *args, **kwargs):

        return cls.instance.ping_url(*args, **kwargs)

    @classmethod
    @validate_implementation_response
    def get_screenshots(cls, *args, **kwargs):

        return cls.instance.get_screenshots(*args, **kwargs)

    @classmethod
    @validate_implementation_response
    def is_screenshot_viewed(cls, *args, **kwargs):

        return cls.instance.is_screenshot_viewed(*args, **kwargs)

    @classmethod
    def post_feedback(cls, *args, **kwargs):

        return cls.instance.post_feedback(*args, **kwargs)

    @classmethod
    def block_url(cls, *args, **kwargs):

        return cls.instance.block_url(*args, **kwargs)

    @classmethod
    def unblock_url(cls, *args, **kwargs):

        return cls.instance.unblock_url(*args, **kwargs)

    @classmethod
    @validate_implementation_response
    def get_http_headers(cls, *args, **kwargs):

        return cls.instance.get_http_headers(*args, **kwargs)
