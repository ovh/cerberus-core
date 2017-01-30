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
    Unit tests for IPTV workflow
"""

import os

from mock import patch

from abuse.models import (Report,
                          Provider,
                          BusinessRules)
from factory import implementations
from tests_ovh import GlobalTestCase

SAMPLES_DIRECTORY = 'tests_ovh/samples'


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
    def test_iptv1_debug_only(self, mock_rq):
        """
            Test iptv1 workflow 1
        """
        from worker import report

        mock_rq.return_value = None
        sample = self._samples['iptv1']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()

        self.assertEqual('Attached', cerberus_report.status)
        self.assertEqual('Open', cerberus_report.ticket.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_iptv1(self, mock_rq):
        """
            Test iptv1 workflow 1
        """
        from worker import report
        rule = BusinessRules.objects.get(name='copyright_iptv_level_1')
        rule.config.pop('debug_only')
        rule.save()

        mock_rq.return_value = None
        sample = self._samples['iptv1']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()

        emails = implementations.get_singleton_of('MailerServiceBase').get_emails(cerberus_report.ticket)
        self.assertEqual(2, len(emails))
        self.assertEqual('Attached', cerberus_report.status)
        self.assertEqual('WaitingAnswer', cerberus_report.ticket.status)
