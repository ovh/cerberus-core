# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016, OVH SAS
#
# This file is part of Cerberus-core.
#
# Cerberus-core is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""
    Test settings for Cerberus
"""

import os

CUSTOM_IMPLEMENTATIONS = (
    'default.adapters.services.storage.impl.FilesystemStorageService',
    'default.adapters.dao.customer.impl.DefaultCustomerDao',
    'default.adapters.services.phishing.impl.DefaultPhishingService',
    'default.adapters.services.mailer.impl.DefaultMailerService',
    'default.adapters.services.action.impl.DefaultActionService',
)

CUSTOM_SCHEDULING_ALGORITHMS = (
    'api.controllers.scheduling.global.GlobalSchedulingAlgorithm',
    'api.controllers.scheduling.limitedOpen.LimitedOpenSchedulingAlgorithm',
)

QUEUE = {
    'default': {
        'name': 'default',
        'default_timeout': 86400,
    },
    'email': {
        'name': 'email',
        'default_timeout': 86400,
    },
    'kpi': {
        'name': 'kpi',
        'default_timeout': 1800,
    },
}

API = {
    'host': '127.0.0.1',
    'port': 6060,
    'forwarded_host': None,
    'use_cache': False,
    'cache_engine': None,  # 'redis' or 'memory'
}

TAGS = {
    'autoarchive': 'distrust:0:autoarchive',
    'attach_only': 'distrust:1:attach_if_exists',
    'no_phishtocheck': 'distrust:2:no_phishtocheck',
    'no_autoack': 'never_auto_ack',
    'phishing_autoblocked': 'phishing:autoblocked',
    'phishing_autoclosed': 'phishing:autoclosed',
    'copyright_autoclosed': 'phishing:autoclosed',
    'phishing_autoreopen': 'phishing:autoreopened',
}

CODENAMES = {
    'ack_received': 'ack_report_received',
    'case_closed': 'case_closed',
    'customer_notification': 'customer_notification',
    'fixed_customer': 'fixed_by_customer',
    'fixed': 'fixed',
    'forward_acns': 'forward_acns',
    'no_more_content': 'no_more_content',
    'phishing_blocked': 'phishing_blocked',
    'service_blocked': 'service_blocked',
    'ticket_closed': 'ticket_closed',
    'not_managed_ip': 'not_managed_ip',
    'invalid': 'invalid',
}

GENERAL_CONFIG = {
    'customer_dao_datetime_format': '%Y-%m-%d %X',
    'email_storage_dir': '/tmp/cerberus_storage_test',
    'cerberus_emails_db': 'cerberus_emails_test.db',
    'bot_user': 'abuse.robot',
    'phishing': {
        'wait': 172800,
        'up_threshold': 0,
        'down_threshold': 75,
    },
    'magic_smtp_header': 'Test-Magic-Smtp-Header',
    'ticket_high_count': 50,
}

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(os.path.dirname(__file__), 'test.db'),
        'TEST_NAME': os.path.join(os.path.dirname(__file__), 'test.db'),
    }
}

PARSING = {
    'providers_to_ignore': [
        'blacklisted@provider.com',
    ],
    'networks_to_ignore': [
        '0.0.0.0/8',
        '224.0.0/4',
    ],
    'domain_to_ignore': [
        'www.yourcompany.com',
    ],
    'fqdn_re': r'(.*\.yourcompany\.com)',
}

TIME_ZONE = 'Europe/Paris'

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
)

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'abuse',
)

SECRET_KEY = 'test'

EMAIL_FETCHER = {
    'cerberus_email': 'ticket+%s.%s@example.com',
    'cerberus_re': r'ticket\+(\w+).(\w+)@example.com',
}

REDIS = {
    'password': '',
    'host': '127.0.0.1',
    'port': '6379',
}

LOG = {
    'handlers': ['stderr'],
}
