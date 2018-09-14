
from functools import wraps

from json import dumps

from flask import g, request
from werkzeug.contrib.cache import RedisCache

from ..models import Role


class Cache(object):

    instance = None
    timeout = 300

    @classmethod
    def set_up(cls, config):
        """
            Set up Cache
        """
        cls.instance = RedisCache(
            host=config['REDIS']['host'],
            port=config['REDIS']['port'],
            password=config['REDIS']['password']
        )

    @classmethod
    def cached(cls, timeout=None, current_user=False):
        """
            Return cached response, update it if timedout
        """
        def decorator(func):
            @wraps(func)
            def decorated_func(*args, **kwargs):
                user = g.user.id if current_user else None
                route = '%s,%s,%s' % (request.path, dumps(request.args), user)
                response = cls.instance.get(unicode(route))
                if response is None:
                    response = func(*args, **kwargs)
                    cls.instance.set(route, response, timeout or cls.timeout)
                return response
            return decorated_func
        return decorator

    @classmethod
    def invalidate(cls, routes, args=None, clear_for_user=False):
        """
            Invalidate cache for given routes
        """
        args = args or {}

        def decorator(func):
            @wraps(func)
            def decorated_func(*fargs, **fkwargs):
                response = func(*fargs, **fkwargs)
                for path in routes:
                    route = '%s,%s,%s' % (path, dumps(args), None)
                    cls.instance.delete(unicode(route))
                    user = fkwargs.get('user', None) if clear_for_user else None
                    if user:
                        route = '%s,%s,%s' % (path, dumps(args), user)
                        cls.instance.delete(unicode(route))
                return response
            return decorated_func
        return decorator


class RoleCache(object):
    """
        Class caching allowed API routes for each `abuse.models.Role`
    """
    routes = {}

    @classmethod
    def set_up(cls):
        """
            Setu up the cache
        """
        for role in Role.objects.all():
            cls.routes[role.codename] = []
            allowed_routes = role.allowedRoutes.all().values_list(
                'method', 'endpoint'
            )
            cls.routes[role.codename] = allowed_routes

    @classmethod
    def is_valid(cls, role, method, endpoint):
        """
            Check if tuple (method, endpoint) for given role exists

            :param str role: The `abuse.models.Role` codename
            :param str method: The HTTP method
            :param str endpoint: The API endpoint
            :rtype: bool
            :return: if allowed or not
        """
        return (method, endpoint) in cls.routes[role]
