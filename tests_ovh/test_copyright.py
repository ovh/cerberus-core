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
    Unit tests for workers functions
"""

import os
from datetime import datetime, timedelta

from django.conf import settings
from mock import patch

from abuse.models import (ServiceAction, ContactedProvider, Report,
                          Provider, Resolution, Ticket, User, UrlStatus,
                          Service, Defendant, BusinessRules, BusinessRulesHistory)
from adapters.services.phishing.abstract import PingResponse
from factory.implementation import ImplementationFactory
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

    @patch('rq.queue.Queue.enqueue')
    @patch('rq_scheduler.scheduler.Scheduler.schedule')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_copyright_trusted_specific_workflow(self, mock_rq_enqueue_in, mock_rq_schedule, mock_rq_enqueue):
        """
            Test copyright workflow and timeout
        """
        from worker import report

        mock_rq_enqueue_in.return_value = None
        mock_rq_schedule.return_value = FakeJob()
        mock_rq_enqueue.return_value = FakeJob()

        sample = self._samples['sample18']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)
        cerberus_report = Report.objects.last()
        cerberus_report.reportItemRelatedReport.all().update(fqdnResolved='1.2.3.4')
        self.assertEqual('Attached', cerberus_report.status)
        self.assertTrue(cerberus_report.ticket)
        self.assertIn('report:copyright_trusted', cerberus_report.tags.all().values_list('name', flat=True))
        self.assertTrue(BusinessRulesHistory.objects.count())

        cerberus_report.status = 'Attached'
        cerberus_report.ticket.status = 'WaitingAnswer'
        cerberus_report.ticket.snoozeDuration = 1
        cerberus_report.ticket.snoozeStart = datetime.now() - timedelta(days=1)
        cerberus_report.ticket.save()
        cerberus_report.save()

        from worker import ticket as ticket_func

        ticket_func.update_waiting()

        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Alarm', ticket.status)
        ticket_func.timeout(ticket.id)
        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Closed', ticket.status)
        self.assertEqual(settings.CODENAMES['fixed'], ticket.resolution.codename)

        # Check if not trusted
        Report.objects.all().delete()
        Ticket.objects.all().delete()
        content = content.replace("Test-Magic-Smtp-Header: it's here", "")
        report.create_from_email(email_content=content, send_ack=False)
        cerberus_report = Report.objects.last()
        self.assertEqual('New', cerberus_report.status)
