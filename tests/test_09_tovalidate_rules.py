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
    Unit tests for tovalidate workflows
"""

import os

from django.conf import settings
from mock import patch

from abuse.models import BusinessRules, Defendant, Report, Service, User
from tests import GlobalTestCase

SAMPLES_DIRECTORY = 'tests/samples'


class FakeJob(object):
    """
        Fake rq job for mock
    """
    def __init__(self):
        self.id = 42
        self.is_finished = True
        self.result = True


class MockRedis(object):
    """
        Mimick a Redis object so unit tests can run
    """
    def __init__(self):
        self.redis = {}

    def set(self, key, *args):

        if key not in self.redis:
            self.redis[key] = []

    def delete(self, key):

        self.redis.pop(key, None)

    def exists(self, key):
        return key in self.redis

    def rpush(self, key, value):

        if key not in self.redis:
            self.redis[key] = [value]
        else:
            self.redis[key].append(value)

    def lrange(self, key, *args):

        if key not in self.redis:
            return []

        return self.redis[key]

    def lrem(self, key, value):
        self.redis[key].remove(value)


class TestWorkers(GlobalTestCase):
    """
        Unit tests for workers functions
    """
    def setUp(self):

        super(TestWorkers, self).setUp()
        self._samples = {}

        for root, dirs, files in os.walk(SAMPLES_DIRECTORY):
            for name in files:
                filename = root + '/' + name
                f = open(filename, 'r')
                self._samples[name] = f

    def tearDown(self):
        for k, v in self._samples.iteritems():
            v.close()

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_tovalidate_invalid(self, mock_rq):
        """
            Check if report is archived when invalidate
        """
        from worker import report

        mock_rq.return_value = None

        sample = self._samples['sample23']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()
        self.assertEqual('ToValidate', cerberus_report.status)
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])
        report.validate_without_defendant(report_id=cerberus_report.id, user_id=user.id)
        cerberus_report = Report.objects.last()
        self.assertEqual('Archived', cerberus_report.status)
        self.assertTrue(cerberus_report.ticket)
        self.assertEqual('Closed', cerberus_report.ticket.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_tovalidate_valid(self, mock_rq):
        """
            Check if report is attached if validate
        """
        from worker import report

        mock_rq.return_value = None

        # Let's create a valid defendant/service first
        sample = self._samples['sample2']
        content = sample.read()
        report.create_from_email(email_content=content)

        # Now create ToValidate report
        sample = self._samples['sample23']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()
        self.assertEqual('ToValidate', cerberus_report.status)

        # Consider operator add items on this report via UX
        cerberus_report.service = Service.objects.last()
        cerberus_report.defendant = Defendant.objects.last()
        cerberus_report.save()

        # Now reparse
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])
        report.validate_with_defendant(report_id=cerberus_report.id, user_id=user.id)
        cerberus_report = Report.objects.last()
        self.assertEqual('Attached', cerberus_report.status)
        self.assertTrue(cerberus_report.ticket)
        self.assertEqual('Open', cerberus_report.ticket.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_rule_debug_option(self, mock_rq):
        """
            Check if debug_only rule params works
        """
        from worker import report

        mock_rq.return_value = None

        rule = BusinessRules.objects.get(name='to_validate')
        rule.config['debug_only'] = 'to_validate'
        rule.save()

        # Now create ToValidate report
        sample = self._samples['sample23']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()
        self.assertEqual('New', cerberus_report.status)
