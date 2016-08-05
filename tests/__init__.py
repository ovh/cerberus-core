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


import os
import shutil

from abuse.models import (AbusePermission, ServiceAction, Category, MailTemplate,
                          Provider, ReportThreshold, User, Profile, Resolution, Tag,
                          Operator, ApiRoute, Role)
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

        MailTemplate.objects.create(
            codename='ack_report_received',
            name='Test template',
            subject='Abuse dectected, Ticket #{{ publicId }}',
            body='Abuse dectected, Ticket #{{ publicId }}',
        )

        MailTemplate.objects.create(
            codename='no_more_content',
            name='No more content',
            subject='No more content',
            body='No more content',
        )

        MailTemplate.objects.create(
            codename='fixed',
            name='Fixed',
            subject='Fixed',
            body='Fixed',
        )

        MailTemplate.objects.create(
            codename='first_alert',
            name='First Alert',
            subject='First Alert',
            body='First Alert',
        )

        MailTemplate.objects.create(
            codename='case_closed',
            name='Case closed',
            subject='Case closed',
            body='Case closed',
        )

        MailTemplate.objects.create(
            codename='service_blocked',
            name='Service blocked',
            subject='Service blocked',
            body='Service blocked',
        )

        MailTemplate.objects.create(
            codename='ticket_closed',
            name='ticket closed',
            subject='ticket closed',
            body='ticket closed',
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
        )

        for tag in ['copyright:autoclosed', 'phishing:autoblocked', 'phishing:autoclosed', 'phishing:autoreopened']:
            Tag.objects.create(codename=tag, name=tag, tagType='Ticket')

        Resolution.objects.create(codename='no_more_content')
        Resolution.objects.create(codename='fixed')
        Resolution.objects.create(codename='forward_acns')
        Resolution.objects.create(codename='fixed_by_customer')

        user = User.objects.create(username=settings.GENERAL_CONFIG['bot_user'])
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.set_password('test')
        user.save()

        profile = Profile.objects.create(name='Expert')
        profile.actions.add(action)
        profile.save()

        for category in Category.objects.all():
            AbusePermission.objects.create(user=user, category=category, profile=profile)

        Provider.objects.create(email='low@provider.com', priority='Low')
        Provider.objects.create(email='normal@provider.com', priority='Normal')
        Provider.objects.create(email='critical@provider.com', priority='Critical')
        Provider.objects.create(email='trusted.phishing@provider.com', priority='Critical', apiKey='token')

        role = Role.objects.create(codename='admin', name='Admin')
        role.modelsAuthorizations = {'ticket': {'schedulingAlgorithm': 'GlobalSchedulingAlgorithm'}}
        role.save()
        Operator.objects.create(role=role, user=user)

        endpoints = [
            'reputation_views.get_url_external_reputation',
            'email_templates_views.get_recipients_type',
            'email_templates_views.get_supported_languages',
            'misc_views.get_providers_priorities',
            'misc_views.get_ticket_priorities',
            'defendant_views.get_defendant_top20',
            'preset_views.order_presets',
            'report_views.bulk_add_reports',
            'ticket_views.get_todo_tickets',
            'ticket_views.bulk_add_tickets',
            'threshold_views.get_all_threshold',
            'threshold_views.create_threshold',
            'misc_views.get_whois',
            'misc_views.get_url_http_headers',
            'misc_views.get_logged_user',
            'tag_views.get_tag_type',
            'email_templates_views.get_all_templates',
            'email_templates_views.create_templates',
            'category_views.get_user_categories',
            'misc_views.get_user_notifications',
            'misc_views.get_mass_contact',
            'misc_views.wrapper',
            'misc_views.get_all_ticket_resolutions',
            'misc_views.add_ticket_resolution',
            'category_views.get_all_categories',
            'category_views.create_category',
            'ticket_views.get_user_tickets',
            'misc_views.get_dashboard',
            'provider_views.get_providers',
            'provider_views.create_provider',
            'misc_views.get_profiles',
            'preset_views.get_all_presets',
            'preset_views.create_preset',
            'misc_views.monitor',
            'misc_views.get_toolbar',
            'report_views.get_all_reports',
            'ticket_views.get_tickets',
            'ticket_views.create_ticket',
            'misc_views.logout',
            'misc_views.search',
            'misc_views.get_all_status',
            'misc_views.get_users_infos',
            'misc_views.auth',
            'misc_views.ping',
            'news_views.get_all_news',
            'news_views.create_news',
            'tag_views.get_all_tags',
            'tag_views.create_tag',
            'reputation_views.get_ip_external_detail',
            'report_views.get_item_screenshot',
            'reputation_views.get_ip_internal_reputation',
            'reputation_views.get_ip_external_reputation',
            'reputation_views.get_ip_tool',
            'reputation_views.get_ip_rbl_reputation',
            'defendant_views.update_or_delete_comment',
            'defendant_views.delete_defendant_tag',
            'provider_views.delete_provider_tag',
            'report_views.get_report_attachment',
            'ticket_views.get_ticket_prefetched_template',
            'ticket_views.update_or_delete_comment',
            'ticket_views.get_actions',
            'ticket_views.get_ticket_prefetched_preset',
            'ticket_views.update_status',
            'report_views.get_all_items_screenshot',
            'report_views.update_report_item',
            'ticket_views.update_ticket_item',
            'ticket_views.update_ticket_proof',
            'report_views.delete_report_tag',
            'ticket_views.delete_ticket_tag',
            'ticket_views.cancel_job',
            'defendant_views.add_comment',
            'defendant_views.get_defendant_services',
            'defendant_views.add_defendant_tag',
            'provider_views.add_provider_tag',
            'ticket_views.update_ticket_snooze',
            'ticket_views.update_ticket_pause',
            'report_views.get_all_report_attachments',
            'report_views.get_dehtmlified_report',
            'ticket_views.update_ticket_defendant',
            'ticket_views.get_providers',
            'report_views.post_feedback',
            'ticket_views.interact',
            'ticket_views.add_comment',
            'ticket_views.get_mails',
            'report_views.get_report_items',
            'report_views.create_report_item',
            'ticket_views.get_ticket_items',
            'ticket_views.get_ticket_proof',
            'report_views.add_report_tag',
            'ticket_views.add_ticket_tag',
            'ticket_views.get_jobs',
            'ticket_views.schedule_job',
            'report_views.get_raw_report',
            'threshold_views.get_threshold',
            'threshold_views.update_threshold',
            'threshold_views.delete_threshold',
            'defendant_views.get_defendant_tickets_stats',
            'defendant_views.get_defendant_reports_stats',
            'misc_views.get_ip_report_count',
            'email_templates_views.get_template',
            'email_templates_views.update_template',
            'misc_views.update_ticket_resolution',
            'misc_views.delete_ticket_resolution',
            'category_views.get_category',
            'category_views.update_category',
            'category_views.delete_category',
            'defendant_views.get_defendant',
            'provider_views.update_provider',
            'preset_views.get_preset',
            'preset_views.update_preset',
            'preset_views.delete_preset',
            'report_views.get_report',
            'report_views.update_report',
            'ticket_views.get_ticket',
            'ticket_views.update_ticket',
            'misc_views.get_status',
            'misc_views.get_user',
            'misc_views.update_user',
            'news_views.get_news',
            'news_views.update_news',
            'news_views.delete_news',
            'tag_views.get_tag',
            'tag_views.update_tag',
            'tag_views.delete_tag'
        ]

        for method in 'GET', 'POST', 'PUT', 'PATCH', 'DELETE':
            for route in endpoints:
                route = ApiRoute.objects.create(method=method, endpoint=route)
                role.allowedRoutes.add(route)

    def tearDown(self):

        shutil.rmtree(settings.GENERAL_CONFIG['email_storage_dir'], ignore_errors=True)
