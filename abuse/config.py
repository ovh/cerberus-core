
import codecs
import json
import os
import sys

import django
import yaml
from django.conf import settings

from .logs import setup_loggers


class Config(object):
    DEBUG = False

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True

    @staticmethod
    def init_app(app):

        Config.init_app(app)

        from .environments import (
            setup_api,
            setup_environments,
            setup_rq_dashboard
        )

        setup_loggers(app)
        setup_environments(app)
        setup_api(app)
        setup_rq_dashboard(app)


class TestingConfig(Config):
    TESTING = True
    DEBUG = True

    @staticmethod
    def init_app(app):
        Config.init_app(app)

        from .environments import (
            setup_api,
            setup_environments,
        )

        setup_environments(app)
        setup_api(app)


class ProductionConfig(Config):
    DEBUG = False

    @staticmethod
    def init_app(app):

        Config.init_app(app)
        setup_loggers(app)

        from .environments import (
            setup_api,
            setup_environments,
            setup_rq_dashboard
        )

        setup_environments(app)
        setup_api(app)
        setup_rq_dashboard(app)


env_config = {
    'dev': DevelopmentConfig,
    'test': TestingConfig,
    'prod': ProductionConfig,
    'default': ProductionConfig
}


def load_config(settings_file, environment='default'):

    config = read_config_from_file(settings_file)

    if not config:
        print('Missing configuration file')
        sys.exit(1)

    # Dango needs to be configured before any Django-related
    # modules import (e.g: models)
    if not settings.configured:
        settings.configure(**config['DJANGO'])
        django.setup()

    return config


def read_config_from_file(settings_file):

    # Locate the config file to use
    if not os.path.isfile(settings_file):
        print('Missing configuration file')
        sys.exit(1)

    # Open and read the config file
    with codecs.open(settings_file, 'r', 'utf8') as file_handler:
        conf = yaml.load(file_handler)
    if conf is None:
        conf = {}
    return conf
