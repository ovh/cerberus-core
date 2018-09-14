
from flask_cors import CORS
from rq_dashboard.cli import add_basic_auth

from .api.cache import Cache, RoleCache
from .api.errors import setup_error_handlers
from .api.middleware import setup_middleware
from .api.views import views_to_register
from .api.views.rqdashboard import blueprint, settings
from .parsers import Parser
from .rules import setup_business_rule_engine
from .services import setup_services
from .tasks import Queues
from .utils.cache import RedisHandler
from .utils.crypto import CryptoHandler
from .utils.networking import NetworkOwnerHandler


def setup_environments(app):

    Parser.set_up(app.config['PARSER'])
    RedisHandler.set_up(app.config['REDIS'])
    CryptoHandler.set_up(app.config['DJANGO']['SECRET_KEY'])
    NetworkOwnerHandler.set_up(app.config['MANAGED_NETWORKS'])
    Queues.set_up(app.config['REDIS'])

    setup_business_rule_engine(app)
    setup_services(app)


def setup_api(app):

    CORS(app)

    for view in views_to_register:
        prefix = '/api{}'.format(view.url_prefix or '')
        app.register_blueprint(view, url_prefix=prefix)

    Cache.set_up(app.config)
    RoleCache.set_up()

    setup_error_handlers(app)
    setup_middleware(app)


def setup_rq_dashboard(app):

    app.config.from_object(settings)
    add_basic_auth(
        blueprint,
        app.config['RQ_DASHBOARD']['username'],
        app.config['RQ_DASHBOARD']['password'],
    )

    app.register_blueprint(blueprint, url_prefix="/api/admin/rq")

    # Force harcoded settings for RQ Dashboard
    app.config['REDIS_HOST'] = app.config['REDIS']['host']
    app.config['REDIS_PORT'] = app.config['REDIS']['port']
    app.config['REDIS_PASSWORD'] = app.config['REDIS']['password']
