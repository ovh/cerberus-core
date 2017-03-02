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


import json
import os

from abuse.models import (AbusePermission, ServiceAction, Category, MailTemplate,
                          Provider, ReportThreshold, User, Profile, Resolution, Tag,
                          Operator, ApiRoute, Role, BusinessRules)
from django.conf import settings
from django.test import TestCase

SAMPLES_DIRECTORY = 'tests/samples'


class GlobalTestCase(TestCase):
    """
        Global setUp for tests
    """
    def setUp(self):

        directory = settings.GENERAL_CONFIG['email_storage_dir']
        if not os.path.exists(directory):
            os.makedirs(directory)

        Category.objects.create(**{'description': u'Illegal', 'name': u'Illegal', 'label': u'Illegal'})
        Category.objects.create(**{'description': u'Intrusion', 'name': u'Intrusion', 'label': u'Intrusion'})
        Category.objects.create(**{'description': u'Malware', 'name': u'Malware', 'label': u'Malware'})
        Category.objects.create(**{'description': u'Network Attack', 'name': u'Network Attack', 'label': u'Network Attack'})
        Category.objects.create(**{'description': u'Other', 'name': u'Other', 'label': u'Other'})
        Category.objects.create(**{'description': u'Phishing', 'name': u'Phishing', 'label': u'Phishing'})
        spam_category = Category.objects.create(**{'description': u'Spam', 'name': u'Spam', 'label': u'Spam'})
        Category.objects.create(**{'description': u'Copyright', 'name': u'Copyright', 'label': u'Copyright'})

        action = ServiceAction.objects.create(
            name='default_action',
            module='VPS',
            level='1',
        )

        ReportThreshold.objects.create(
            category=spam_category,
            threshold=100,
            interval=3600,
        )

        for tag in ['copyright:autoclosed', 'phishing:autoblocked', 'phishing:autoclosed', 'phishing:autoreopened']:
            Tag.objects.create(codename=tag, name=tag, tagType='Ticket')
            Tag.objects.create(codename=tag, name=tag, tagType='Report')

        Resolution.objects.create(codename='no_more_content')
        Resolution.objects.create(codename='invalid')
        Resolution.objects.create(codename='fixed')
        Resolution.objects.create(codename='forward_acns')
        Resolution.objects.create(codename='fixed_by_customer')

        Provider.objects.create(email='low@provider.com', priority='Low')
        Provider.objects.create(email='normal@provider.com', priority='Normal')
        Provider.objects.create(email='critical@provider.com', priority='Critical')
        Provider.objects.create(email='trusted.phishing@provider.com', priority='Critical', apiKey='token')

        set_email_templates()
        set_business_rules()
        set_roles()


def set_email_templates():

    MailTemplate.objects.create(
        codename='ack_report_received',
        name='Test template',
        subject='Abuse received, Ticket #{{ publicId }}',
        body='Abuse received, Ticket #{{ publicId }}',
        recipientType='Plaintiff',
    )

    MailTemplate.objects.create(
        codename='no_more_content',
        name='No more content',
        subject='No more content',
        body='No more content',
        recipientType='Plaintiff',
    )

    MailTemplate.objects.create(
        codename='fixed',
        name='Fixed',
        subject='Fixed',
        body='Fixed',
        recipientType='Defendant',
    )

    MailTemplate.objects.create(
        codename='customer_notification',
        name='Abuse detected',
        subject='Abuse detected',
        body="""-- start of the technical details --
            {% if proof|length == 1 %}{% for p in proof %}{{ p }}{% endfor %}{% else %}{% for p in proof %}
            {{ p }}
            ----------{% endfor %}{% endif %}""",
        recipientType='Defendant',
    )

    MailTemplate.objects.create(
        codename='case_closed',
        name='Case closed',
        subject='Case closed',
        body='Case closed',
        recipientType='Plaintiff',
    )

    MailTemplate.objects.create(
        codename='service_blocked',
        name='Service blocked',
        subject='Service blocked',
        body='Service blocked',
        recipientType='Defendant',
    )

    MailTemplate.objects.create(
        codename='not_managed_ip',
        name='not_managed_ip',
        subject='not_managed_ip',
        body='not_managed_ip',
        recipientType='Plaintiff',
    )

    MailTemplate.objects.create(
        codename='ticket_closed',
        name='ticket closed',
        subject='ticket closed',
        body='ticket closed',
        recipientType='Defendant',
    )

    MailTemplate.objects.create(
        codename='cloudflare_ip_request',
        name='Cloudflare ip request',
        subject='Cloudflare ip request',
        body='Cloudflare ip request',
        recipientType='Other',
    )

    MailTemplate.objects.create(
        codename='phishing_blocked',
        name='phishing blocked',
        subject='phishing blocked',
        body="""{% if phishingUrls|length > 0 %}
              Below is the list of URLs pointing to the phishing webpage you're hosting :\n
              {% for url in phishingUrls %}
              \n* {{ url }}
              {% endfor %}
              {% endif %}""",
        recipientType='Defendant',
    )


def set_roles():

    user = User.objects.create(username=settings.GENERAL_CONFIG['bot_user'])
    user.is_superuser = True
    user.is_staff = True
    user.is_active = True
    user.set_password('test')
    user.save()

    action = ServiceAction.objects.get(name='default_action')
    profile = Profile.objects.create(name='Expert')
    profile.actions.add(action)
    profile.save()

    for category in Category.objects.all():
        AbusePermission.objects.create(user=user, category=category, profile=profile)

    role = Role.objects.create(codename='admin', name='Admin')
    role.modelsAuthorizations = {'ticket': {'schedulingAlgorithm': 'GlobalSchedulingAlgorithm'}}
    role.save()
    Operator.objects.create(role=role, user=user)

    endpoints = [
        'threshold_views.get_all_threshold',
        'report_views.validate_report',
        'preset_views.create_preset',
        'ticket_views.update_ticket_proof',
        'tag_views.get_all_tags',
        'email_templates_views.create_templates',
        'reputation_views.get_ip_rbl_reputation',
        'email_templates_views.get_all_templates',
        'ticket_views.get_actions',
        'ticket_views.update_ticket_item',
        'misc_views.get_user_notifications',
        'ticket_views.delete_ticket_tag',
        'ticket_views.get_ticket_prefetched_template',
        'provider_views.delete_provider_tag',
        'email_templates_views.get_recipients_type',
        'ticket_views.get_ticket',
        'news_views.get_all_news',
        'report_views.update_report',
        'news_views.get_news',
        'email_templates_views.get_supported_languages',
        'misc_views.get_user',
        'ticket_views.add_items_to_proof',
        'report_views.delete_report_tag',
        'misc_views.get_providers_priorities',
        'tag_views.delete_tag',
        'misc_views.get_url_http_headers',
        'ticket_views.get_ticket_attachments',
        'threshold_views.update_threshold',
        'misc_views.monitor',
        'ticket_views.update_ticket',
        'defendant_views.get_defendant_tickets_stats',
        'misc_views.get_all_ticket_resolutions',
        'report_views.get_all_reports',
        'ticket_views.cancel_job',
        'preset_views.get_preset',
        'defendant_views.add_comment',
        'email_templates_views.update_template',
        'tag_views.get_tag_type',
        'defendant_views.get_defendant_top20',
        'ticket_views.get_providers',
        'ticket_views.add_ticket_tag',
        'provider_views.get_providers',
        'threshold_views.delete_threshold',
        'ticket_views.update_ticket_pause',
        'misc_views.get_cerberus_roles',
        'preset_views.update_preset',
        'ticket_views.get_ticket_items',
        'tag_views.update_tag',
        'defendant_views.update_or_delete_comment',
        'misc_views.update_ticket_resolution',
        'report_views.get_all_report_attachments',
        'ticket_views.update_ticket_defendant',
        'report_views.get_raw_report',
        'ticket_views.update_or_delete_comment',
        'report_views.post_feedback',
        'misc_views.get_profiles',
        'ticket_views.schedule_job',
        'provider_views.add_provider_tag',
        'ticket_views.unblock_ticket_item',
        'defendant_views.add_defendant_tag',
        'ticket_views.bulk_add_tickets',
        'misc_views.delete_ticket_resolution',
        'report_views.get_report',
        'preset_views.order_presets',
        'defendant_views.get_defendant_reports_stats',
        'misc_views.update_user',
        'category_views.get_all_categories',
        'ticket_views.get_todo_tickets',
        'provider_views.update_provider',
        'reputation_views.get_url_external_reputation',
        'reputation_views.get_ip_external_detail',
        'preset_views.delete_preset',
        'report_views.bulk_add_reports',
        'category_views.create_category',
        'misc_views.logout',
        'category_views.get_user_categories',
        'news_views.update_news',
        'misc_views.add_ticket_resolution',
        'misc_views.get_dashboard',
        'defendant_views.get_defendant',
        'misc_views.get_logged_user',
        'tag_views.get_tag',
        'ticket_views.get_ticket_proof',
        'misc_views.auth',
        'category_views.update_category',
        'ticket_views.get_user_tickets',
        'ticket_views.get_ticket_attachment',
        'report_views.add_report_tag',
        'email_templates_views.get_template',
        'ticket_views.update_status',
        'category_views.get_category',
        'ticket_views.create_ticket',
        'tag_views.create_tag',
        'ticket_views.get_ticket_prefetched_preset',
        'ticket_views.get_jobs',
        'misc_views.search',
        'news_views.delete_news',
        'misc_views.get_all_status',
        'misc_views.get_mass_contact',
        'misc_views.get_users_infos',
        'ticket_views.update_ticket_snooze',
        'misc_views.get_whois',
        'report_views.get_dehtmlified_report',
        'provider_views.create_provider',
        'category_views.delete_category',
        'report_views.get_report_attachment',
        'report_views.get_all_items_screenshot',
        'reputation_views.get_ip_external_reputation',
        'report_views.update_report_item',
        'report_views.create_report_item',
        'report_views.unblock_report_item',
        'reputation_views.get_ip_internal_reputation',
        'misc_views.ping',
        'threshold_views.get_threshold',
        'threshold_views.create_threshold',
        'defendant_views.delete_defendant_tag',
        'defendant_views.get_defendant_services',
        'misc_views.get_ip_report_count',
        'misc_views.wrapper',
        'ticket_views.interact',
        'ticket_views.get_mails',
        'report_views.get_report_items',
        'ticket_views.get_timeline',
        'preset_views.get_all_presets',
        'ticket_views.ticket_star_management',
        'misc_views.get_ticket_priorities',
        'misc_views.get_toolbar',
        'report_views.get_item_screenshot',
        'ticket_views.get_tickets',
        'news_views.create_news',
        'ticket_views.add_comment',
        'reputation_views.get_ip_tool',
        'misc_views.get_status',
    ]

    for method in 'GET', 'POST', 'PUT', 'PATCH', 'DELETE':
        for route in endpoints:
            route = ApiRoute.objects.create(method=method, endpoint=route)
            role.allowedRoutes.add(route)


def set_business_rules():

    for dirpath, _, files in os.walk(os.path.dirname(os.path.realpath(__file__)) + '/rules'):
        for _file in files:
            if _file.endswith(".json"):
                with open(os.path.join(dirpath, _file), 'r') as file_reader:
                    config = json.loads(file_reader.read())
                BusinessRules.objects.create(**config)
