
from time import sleep

from requests.exceptions import (ChunkedEncodingError, ConnectionError,
                                 HTTPError, Timeout)
from simplejson import JSONDecodeError


def get(url, **kwargs):

    return _wrapper(url, method='GET', **kwargs)


def post(url, **kwargs):

    return _wrapper(url, method='POST', **kwargs)


def put(url, **kwargs):

    return _wrapper(url, method='PUT', **kwargs)


class RequestException(Exception):
    """
        RequestException
    """
    def __init__(self, message, code=None, response=None):
        super(RequestException, self).__init__(message)
        self.code = code
        self.response = response


def _wrapper(url, method='GET', auth=None, params=None,
             as_dict=True, headers=None, timeout=30,
             requests_lib='requests', **kwargs):
    """
        Python-requests wrapper
    """
    response = None
    func_params = {
        'headers': headers,
        'auth': auth,
        'params': params,
        'data': params,
        'verify': True,
        'timeout': timeout,
    }
    func_params.update(**kwargs)

    # Because sometimes network or backend is instable (TCP RST, HTTP 500 ...)
    max_tries = 3

    for retry in range(max_tries):
        try:
            if method == 'GET':
                func_params.pop('data', None)
            else:
                func_params.pop('params', None)

            func = getattr(__import__(requests_lib), method.lower())
            response = func(url, **func_params)
            response.raise_for_status()
            if as_dict:
                return response.json()
            return response
        except HTTPError as ex:
            if 500 <= int(ex.response.status_code) <= 599:
                if retry == max_tries - 1:
                    raise RequestException(
                        _get_exception(response, ex),
                        ex.response.status_code
                    )
                sleep(2)
            else:
                raise RequestException(
                    _get_exception(response, ex),
                    ex.response.status_code,
                    response=response
                )
        except Timeout as ex:
            if retry == max_tries - 1:
                raise RequestException(_get_exception(response, ex))
        except (ChunkedEncodingError, ConnectionError, JSONDecodeError) as ex:
            if retry == max_tries - 1:
                raise RequestException(_get_exception(response, ex))
            sleep(1)


def _get_exception(response, exception):
    """
        Try to extract message from requests exception
    """
    try:
        data = response.json()
        message = data['message']
    except:
        message = str(exception)

    return message
