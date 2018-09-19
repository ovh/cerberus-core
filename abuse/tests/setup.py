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
    Init for tests
"""

import os

import yaml

from mock import Mock

from django.core.management import call_command
from django.test import TestCase


class FakeJob(object):
    """
        Fake rq job for mock
    """

    def __init__(self):
        self.id = 42
        self.is_finished = True
        self.result = True


class CerberusTest(TestCase):
    """Initialize db for unit tests.

    Before each test truncate the content of the database, but keep the schema.
    """

    @classmethod
    def setUpClass(cls):

        setup_db()

        cls.patch_enqueue = ["rq.Queue.enqueue", Mock(return_value=FakeJob())]

        cls.patch_current_job = ["rq.job.get_current_job", Mock(return_value=FakeJob())]

        cls.patch_enqueue_in = [
            "rq_scheduler.scheduler.Scheduler.enqueue_in",
            Mock(return_value=FakeJob()),
        ]

        cls.patch_getnotif = [
            "abuse.utils.cache.get_user_notifications",
            Mock(return_value=[]),
        ]

        cls.patch_api_cache_get = [
            "abuse.api.cache.Cache.instance.get",
            Mock(return_value=None),
        ]

        cls.patch_api_cache_set = [
            "abuse.api.cache.Cache.instance.set",
            Mock(return_value=None),
        ]

        cls.patch_api_cache_delete = [
            "abuse.api.cache.Cache.instance.delete",
            Mock(return_value=None),
        ]

    @classmethod
    def tearDownClass(cls):

        call_command("flush", verbosity=0, interactive=False, out="/dev/null")


def setup_db():

    from ..models import (
        AbusePermission,
        ServiceAction,
        Category,
        MailTemplate,
        Provider,
        ReportThreshold,
        User,
        Profile,
        Resolution,
        Tag,
        Operator,
        ApiRoute,
        Role,
        BusinessRules,
    )

    Category.create(
        **{"description": u"Illegal", "name": u"Illegal", "label": u"Illegal"}
    )
    Category.create(
        **{"description": u"Intrusion", "name": u"Intrusion", "label": u"Intrusion"}
    )
    Category.create(
        **{"description": u"Malware", "name": u"Malware", "label": u"Malware"}
    )
    Category.create(
        **{
            "description": u"Network Attack",
            "name": u"Network Attack",
            "label": u"Network Attack",
        }
    )
    Category.create(**{"description": u"Other", "name": u"Other", "label": u"Other"})
    Category.create(
        **{"description": u"Phishing", "name": u"Phishing", "label": u"Phishing"}
    )
    spam_category = Category.create(
        **{"description": u"Spam", "name": u"Spam", "label": u"Spam"}
    )
    Category.create(
        **{"description": u"Copyright", "name": u"Copyright", "label": u"Copyright"}
    )

    action = ServiceAction.get_or_create(name="default_action", module="VPS", level="1")

    ReportThreshold.create(category=spam_category, threshold=100, interval=3600)

    for tag in (
        "distrust:0:autoarchive",
        "distrust:1:attach_if_exists",
        "distrust:2:no_phishtocheck",
        "never_auto_ack",
    ):
        Tag.create(codename=tag, name=tag, tagType="Provider")

    for tag in (
        "copyright:autoclosed",
        "phishing:autoblocked",
        "phishing:autoclosed",
        "phishing:autoreopened",
    ):
        Tag.create(codename=tag, name=tag, tagType="Ticket")
        Tag.create(codename=tag, name=tag, tagType="Report")

    Resolution.create(codename="no_more_content")
    Resolution.create(codename="invalid")
    Resolution.create(codename="fixed")
    Resolution.create(codename="forward_acns")
    Resolution.create(codename="fixed_by_customer")

    Provider.create(email="low@provider.com", priority="Low")
    Provider.create(email="normal@provider.com", priority="Normal")
    Provider.create(email="critical@provider.com", priority="Critical")
    Provider.create(
        email="trusted.phishing@provider.com", priority="Critical", apiKey="token"
    )
    Provider.create(
        email="supertrusted@copyrightprovider.com", priority="High", trusted=True
    )

    MailTemplate.create(
        codename="ack_report_received",
        name="Test template",
        subject="Abuse received, Ticket #{{ publicId }}",
        body="Abuse received, Ticket #{{ publicId }}",
        recipientType="Plaintiff",
    )

    MailTemplate.create(
        codename="no_more_content",
        name="No more content",
        subject="No more content",
        body="No more content",
        recipientType="Plaintiff",
    )

    MailTemplate.create(
        codename="fixed",
        name="Fixed",
        subject="Fixed",
        body="Fixed",
        recipientType="Defendant",
    )

    MailTemplate.create(
        codename="customer_notification",
        name="Abuse detected",
        subject="Abuse detected",
        body="""-- start of the technical details --
            {% if proof|length == 1 %}{% for p in proof %}{{ p }}{% endfor %}{% else %}{% for p in proof %}
            {{ p }}
            ----------{% endfor %}{% endif %}""",
        recipientType="Defendant",
    )

    MailTemplate.create(
        codename="case_closed",
        name="Case closed",
        subject="Case closed",
        body="Case closed",
        recipientType="Plaintiff",
    )

    MailTemplate.create(
        codename="service_blocked",
        name="Service blocked",
        subject="Service blocked",
        body="Service blocked",
        recipientType="Defendant",
    )

    MailTemplate.create(
        codename="not_managed_ip",
        name="not_managed_ip",
        subject="not_managed_ip",
        body="not_managed_ip",
        recipientType="Plaintiff",
    )

    MailTemplate.create(
        codename="ticket_closed",
        name="ticket closed",
        subject="ticket closed",
        body="ticket closed",
        recipientType="Defendant",
    )

    MailTemplate.create(
        codename="cloudflare_ip_request",
        name="Cloudflare ip request",
        subject="Cloudflare ip request",
        body="Cloudflare ip request",
        recipientType="Other",
    )

    MailTemplate.create(
        codename="phishing_blocked",
        name="phishing blocked",
        subject="phishing blocked",
        body="""{% if phishingUrls|length > 0 %}
              Below is the list of URLs pointing to the phishing webpage you're hosting :\n
              {% for url in phishingUrls %}
              \n* {{ url }}
              {% endfor %}
              {% endif %}""",
        recipientType="Defendant",
    )

    user = User.objects.create(username="abuse.robot")
    user.is_superuser = True
    user.is_staff = True
    user.is_active = True
    user.set_password("test")
    user.save()

    action = ServiceAction.get(name="default_action")
    profile = Profile.create(name="Expert")
    profile.actions.add(action)
    profile.save()

    for category in Category.all():
        AbusePermission.create(user=user, category=category, profile=profile)

    role = Role.create(codename="admin", name="Admin")
    role.modelsAuthorizations = {
        "ticket": {"schedulingAlgorithm": "GlobalSchedulingAlgorithm"}
    }
    role.save()
    Operator.create(role=role, user=user)

    endpoints = [
        "category_views.create_category",
        "category_views.delete_category",
        "category_views.get_all_categories",
        "category_views.get_category",
        "category_views.get_user_categories",
        "category_views.update_category",
        "defendant_views.add_comment",
        "defendant_views.add_defendant_tag",
        "defendant_views.delete_defendant_tag",
        "defendant_views.get_defendant",
        "defendant_views.get_defendant_services",
        "defendant_views.get_defendant_top20",
        "defendant_views.update_or_delete_comment",
        "email_templates_views.create_templates",
        "email_templates_views.get_all_templates",
        "email_templates_views.get_recipients_type",
        "email_templates_views.get_supported_languages",
        "email_templates_views.get_template",
        "email_templates_views.update_template",
        "misc_views.add_ticket_resolution",
        "misc_views.auth",
        "misc_views.delete_ticket_resolution",
        "misc_views.get_all_status",
        "misc_views.get_all_ticket_resolutions",
        "misc_views.get_cerberus_roles",
        "misc_views.get_dashboard",
        "misc_views.get_logged_user",
        "misc_views.get_mass_contact",
        "misc_views.get_profiles",
        "misc_views.get_providers_priorities",
        "misc_views.get_status",
        "misc_views.get_ticket_priorities",
        "misc_views.get_toolbar",
        "misc_views.get_url_http_headers",
        "misc_views.get_user",
        "misc_views.get_user_notifications",
        "misc_views.get_user_tickets",
        "misc_views.get_users_infos",
        "misc_views.get_whois",
        "misc_views.logout",
        "misc_views.monitor",
        "misc_views.ping",
        "misc_views.post_mass_contact",
        "misc_views.search",
        "misc_views.update_ticket_resolution",
        "misc_views.update_user",
        "news_views.create_news",
        "news_views.delete_news",
        "news_views.get_all_news",
        "news_views.get_news",
        "news_views.update_news",
        "preset_views.create_preset",
        "preset_views.delete_preset",
        "preset_views.get_all_presets",
        "preset_views.get_preset",
        "preset_views.order_presets",
        "preset_views.update_preset",
        "provider_views.add_provider_tag",
        "provider_views.create_provider",
        "provider_views.delete_provider_tag",
        "provider_views.get_providers",
        "provider_views.update_provider",
        "report_views.add_report_tag",
        "report_views.bulk_add_reports",
        "report_views.create_report_item",
        "report_views.delete_report_tag",
        "report_views.get_all_items_screenshot",
        "report_views.get_all_report_attachments",
        "report_views.get_all_reports",
        "report_views.get_dehtmlified_report",
        "report_views.get_item_screenshot",
        "report_views.get_raw_report",
        "report_views.get_report",
        "report_views.get_report_attachment",
        "report_views.get_report_items",
        "report_views.post_feedback",
        "report_views.unblock_report_item",
        "report_views.update_report",
        "report_views.update_report_item",
        "report_views.validate_report",
        "reputation_views.get_ip_external_detail",
        "reputation_views.get_ip_external_reputation",
        "reputation_views.get_ip_internal_reputation",
        "reputation_views.get_ip_rbl_reputation",
        "reputation_views.get_ip_tool",
        "reputation_views.get_url_external_reputation",
        "tag_views.create_tag",
        "tag_views.delete_tag",
        "tag_views.get_all_tags",
        "tag_views.get_tag",
        "tag_views.get_tag_type",
        "tag_views.update_tag",
        "threshold_views.create_threshold",
        "threshold_views.delete_threshold",
        "threshold_views.get_all_threshold",
        "threshold_views.get_threshold",
        "threshold_views.update_threshold",
        "ticket_views.add_comment",
        "ticket_views.add_items_to_proof",
        "ticket_views.add_ticket_tag",
        "ticket_views.bulk_add_tickets",
        "ticket_views.cancel_job",
        "ticket_views.delete_ticket_tag",
        "ticket_views.get_actions",
        "ticket_views.get_mails",
        "ticket_views.get_providers",
        "ticket_views.get_ticket",
        "ticket_views.get_ticket_attachment",
        "ticket_views.get_ticket_attachments",
        "ticket_views.get_ticket_items",
        "ticket_views.get_ticket_prefetched_preset",
        "ticket_views.get_ticket_prefetched_template",
        "ticket_views.get_ticket_proof",
        "ticket_views.get_tickets",
        "ticket_views.get_timeline",
        "ticket_views.get_todo_tickets",
        "ticket_views.interact",
        "ticket_views.ticket_star_management",
        "ticket_views.unblock_ticket_item",
        "ticket_views.update_or_delete_comment",
        "ticket_views.update_status",
        "ticket_views.update_ticket",
        "ticket_views.update_ticket_defendant",
        "ticket_views.update_ticket_item",
        "ticket_views.update_ticket_pause",
        "ticket_views.update_ticket_proof",
        "ticket_views.update_ticket_snooze",
    ]

    for method in "GET", "POST", "PUT", "PATCH", "DELETE":
        for route in endpoints:
            route = ApiRoute.create(method=method, endpoint=route)
            role.allowedRoutes.add(route)

    for dirpath, _, files in os.walk("abuse/rules/definitions"):
        for _file in files:
            if _file.endswith(".yaml") and not _file.startswith("ovh_"):
                with open(os.path.join(dirpath, _file), "r") as file_reader:
                    config = yaml.load(file_reader.read())
                BusinessRules.create(**config)

    from ..api.cache import RoleCache

    RoleCache.set_up()
