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
    Settings for Cerberus
"""


import os


# ################################ Cerberus Settings ##################################

# Main Cerberus Configuration
#
# Do not forget EMAIL_STORAGE_DIR ENV (default '/tmp/cerberus_storage_dir')
#
# What's 'magic_smtp_header' ? : A header your SMTP header can add to email depending on sender/mailbox/country etc ...
#
#   It's used to know if an email can be trusted

GENERAL_CONFIG = {
    'customer_dao_datetime_format': '%Y-%m-%d %X',
    'email_storage_dir': os.getenv('EMAIL_STORAGE_DIR', '/tmp/cerberus_storage'),
    'cerberus_emails_db': 'cerberus_emails.db',
    'bot_user': 'abuse.robot',
    'phishing': {
        'wait': 172800,
        'up_threshold': 0,
        'down_threshold': 75,
    },
    'magic_smtp_header': os.getenv('MAGIC_SMTP_HEADER', 'X-MAGIC-SMTP-HEADER-TO-IDENTIFY-TRUSTED-PROVIDER'),
    'report_timeout': 30,
}

# API Config (via ENV)
#
# What's FORWARDED_HOST ? For security reason, if you use different host for Cerberus-UX and Cerberus-API (not required)
#
API = {
    'host': os.getenv('API_HOST', '127.0.0.1'),
    'port': os.getenv('API_PORT', 6060),
    'forwarded_host': os.getenv('FORWARDED_HOST'),
}

# Defined here your customer adapters implementations. For testing you cans use provided default impl
#
# Required are :
#       adapters.services.storage
#       adapters.dao.customer
#       adapters.services.phishing
#       adapters.services.mailer
#       adapters.services.action

CUSTOM_IMPLEMENTATIONS = (
    'default.adapters.services.storage.impl.FilesystemStorageService',
    'default.adapters.dao.customer.impl.DefaultCustomerDao',
    'default.adapters.services.phishing.impl.DefaultPhishingService',
    'default.adapters.services.mailer.impl.DefaultMailerService',
    'default.adapters.services.action.impl.DefaultActionService',
)

# Cerberus use a lot of 'tags',required are here with their mapping to default provided data
#
TAGS = {
    'autoarchive': 'distrust:0:autoarchive',
    'attach_only': 'distrust:1:attach_if_exists',
    'no_phishtocheck': 'distrust:2:no_phishtocheck',
    'no_autoack': 'never_auto_ack',
    'phishing_autoblocked': 'phishing:autoblocked',
    'phishing_autoclosed': 'phishing:autoclosed',
    'phishing_autoreopen': 'phishing:autoreopened',
    'phishing_toblock': 'phishing:toblock',
}

# Cerberus use a lot of 'codenames',required are here with their mapping to default provided data
#
CODENAMES = {
    'ack_received': 'ack_report_received',
    'case_closed': 'case_closed',
    'first_alert': 'first_alert',
    'fixed_customer': 'fixed_by_customer',
    'fixed': 'fixed_by_isp',
    'forward_acns': 'forward_acns',
    'no_more_content': 'no_more_content',
    'phishing_blocked': 'phishing_blocked',
    'phishing_service_blocked': 'phishing_service_blocked',
    'ticket_closed': 'ticket_closed',
}

# Above all, Cerberus is basically an abuse's email fetcher
#
# This settings are required (using IMAP)
#
# cerberus_email: The email to use for sending email to defendant
#
# cerberus_re: Regex to know if the email is an anwser to a Cerberus Ticket
#
EMAIL_FETCHER = {
    'host': os.getenv('EMAIL_HOST'),
    'port': os.getenv('EMAIL_PORT', 993),
    'login': os.getenv('EMAIL_LOGIN'),
    'pass': os.getenv('EMAIL_PASS'),
    'cerberus_email': 'ticket+%s.%s@company.com',
    'cerberus_re': r'ticket\+(\w+).(\w+)@company.com',
}

# Parsing settings
#
# 'domain_to ignore': Very usefull to ignore wrong/invalid/unwanted domain when parsing email content
#
# 'fqdn_re': of course trying to identify a FQDN in an text can generate a huge amount of false positive
#           maybe you have a regexp to identify YOUR managed FQDN (i.e: endswith domain.com)
PARSING = {
    'domain_to_ignore': [
        'www.yourcompany.com',
    ],
    'fqdn_re': r'(.*\.yourcompany\.com)',
}

# Redis needed for Worker/API
#
REDIS = {
    'user': os.getenv('REDIS_USER'),
    'password': os.getenv('REDIS_PASS'),
    'host': os.getenv('REDIS_HOST', '127.0.0.1'),
    'port': os.getenv('REDIS_PORT', 6379),
    'name': os.getenv('REDIS_NAME'),
}

# You can use 'stderr' or 'gelf' or both
#
LOG = {
    'handlers': ['stderr'],  # or ['gelf'] or ['stderr', 'gelf']

    'gelf': {
        'host': os.getenv('GELF_HOST', '0.0.0.0'),
        'port': int(os.getenv('GELF_PORT', 12345)),
        'static_fields': {
            os.getenv('GELF_FIELD', 'test_field'): os.getenv('GELF_VALUE', 'test_value'),
        }
    },
}

# ################################ Django Settings ##################################

# You need to edit this !!

SECRET_KEY = os.getenv('SECRET_KEY', 'test')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.getenv('PG_NAME', 'abuse'),
        'USER': os.getenv('PG_USER', 'cerberus'),
        'PASSWORD': os.getenv('PG_PASS', 'cerberus'),
        'HOST': os.getenv('PG_HOST', '127.0.0.1'),
        'PORT': os.getenv('PG_PORT', 5432),
    }
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
