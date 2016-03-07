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
                          ReportThreshold, User, Profile, Resolution, Tag)
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
            codename='phishing_service_blocked',
            name='Phishing blocked',
            subject='Phishing blocked',
            body='Phishing blocked',
        )

        for tag in ['phishing:autoblocked', 'phishing:autoclosed', 'phishing:autoreopened']:
            Tag.objects.create(codename=tag, name=tag, tagType='Ticket')

        Resolution.objects.create(codename='no_more_content')
        Resolution.objects.create(codename='fixed')
        Resolution.objects.create(codename='forward_acns')

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

    def tearDown(self):

        shutil.rmtree(settings.GENERAL_CONFIG['email_storage_dir'], ignore_errors=True)
