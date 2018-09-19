
import json
import sys
import traceback

from flask import Response


def setup_error_handlers(api):
    def format_error(code, message):
        content = {"message": message}
        return Response(
            json.dumps(content), status=code, content_type="application/json"
        )

    @api.errorhandler(400)
    def bad_request_handler(exception):
        return format_error(400, exception.description)

    @api.errorhandler(401)
    def unauthorized_handler(exception):
        return format_error(401, exception.description)

    @api.errorhandler(403)
    def forbidden_handler(exception):
        return format_error(403, exception.description)

    @api.errorhandler(404)
    def not_found_handler(exception):
        return format_error(404, exception.description)

    @api.errorhandler(500)
    def internal_error_handler(exception):
        return format_error(500, exception.description)

    @api.errorhandler(Exception)
    def unhandled_exception(exception):

        exception_infos = sys.exc_info()
        exception_tb = traceback.extract_tb(exception_infos[2])[-1]
        msg = "error: 'type' {} - 'msg' {} - 'file' {} - 'line' {} - 'func' {}"
        msg = msg.format(
            type(exception).__name__,
            str(exception),
            exception_tb[0],
            exception_tb[1],
            exception_tb[2],
        )
        api.logger.warning(msg)
        api.logger.debug(msg)
        api.logger.info(msg)
        print msg

        return format_error(500, "Internal Server Error")
