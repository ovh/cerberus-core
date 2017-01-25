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
    @patch('utils.utils.redis', new_callable=MockRedis)
    @patch('utils.utils.get_ips_from_fqdn')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_tovalidate_cloudflare_request(self, mock_rq, mock_utils, mock_redis, mock_enqueue):
        """
            Test Cloudflare request workflow
        """
        from worker import report

        mock_rq.return_value = None
        mock_utils.return_value = ['103.21.244.1']
        mock_enqueue.return_value = FakeJob()

        # Create report
        sample = self._samples['sample23']
        content_to_request = sample.read()
        report.create_from_email(email_content=content_to_request, send_ack=True)
        cerberus_report = Report.objects.last()
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

        # Apply cdn request workflow
        report.cdn_request(
            report_id=cerberus_report.id,
            user_id=user.id,
            domain_to_request='www.cdnproxy-protected-domain.com'
        )

        cerberus_report = Report.objects.last()
        self.assertEqual('Attached', cerberus_report.status)
        self.assertTrue(cerberus_report.ticket)

        cerberus_ticket = Ticket.objects.last()
        emails = ImplementationFactory.instance.get_singleton_of(
            'MailerServiceBase'
        ).get_emails(
            cerberus_ticket
        )
        self.assertEqual(cerberus_ticket.treatedBy, user)
        self.assertEqual(1, len(emails))
        recipient = emails[0].sender

        # Fake Cloudflare response and parse response
        sample = self._samples['sample24']
        content = sample.read()
        content = content.replace('ticket+toreplace@example.com', recipient)
        report.create_from_email(email_content=content, send_ack=True)

        # Now ticket have a defendant/service
        cerberus_report = Report.objects.last()
        cerberus_ticket = Ticket.objects.last()
        self.assertTrue(cerberus_report.service)
        self.assertTrue(cerberus_report.defendant)

        # Try use cache for new request
        report.create_from_email(email_content=content_to_request, send_ack=True)
        cerberus_report = Report.objects.last()
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

        report.cdn_request(
            report_id=cerberus_report.id,
            user_id=user.id,
            domain_to_request='www.cdnproxy-protected-domain.com'
        )

        cerberus_report = Report.objects.last()
        self.assertEqual('Attached', cerberus_report.status)
        self.assertTrue(cerberus_report.service)
        self.assertTrue(cerberus_report.defendant)

    @patch('rq.queue.Queue.enqueue')
    @patch('utils.utils.redis', new_callable=MockRedis)
    @patch('utils.utils.get_ips_from_fqdn')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_tovalidate_cloudflare_request_2(self, mock_rq, mock_utils, mock_redis, mock_enqueue):
        """
            Testing two consecutive TovVlidate Cloudflare case
        """
        from worker import report

        mock_rq.return_value = None
        mock_utils.return_value = ['103.21.244.1']
        mock_enqueue.return_value = FakeJob()

        # Create report
        sample = self._samples['sample23']
        content_to_request = sample.read()

        for _ in xrange(2):
            report.create_from_email(email_content=content_to_request, send_ack=True)
            cerberus_report = Report.objects.last()
            user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

            # Apply cdn request workflow
            report.cdn_request(
                report_id=cerberus_report.id,
                user_id=user.id,
                domain_to_request='www.cdnproxy-protected-domain.com'
            )

        cerberus_ticket = Ticket.objects.last()
        emails = ImplementationFactory.instance.get_singleton_of(
            'MailerServiceBase'
        ).get_emails(
            cerberus_ticket
        )
        self.assertEqual(cerberus_ticket.treatedBy, user)
        self.assertEqual(1, len(emails))
        self.assertEqual(2, cerberus_ticket.reportTicket.count())
        recipient = emails[0].sender

        # Fake Cloudflare response and parse response
        sample = self._samples['sample24']
        content = sample.read()
        content = content.replace('ticket+toreplace@example.com', recipient)
        report.create_from_email(email_content=content, send_ack=True)

        # Now ticket have a defendant/service
        cerberus_report = Report.objects.last()
        cerberus_ticket = Ticket.objects.last()
        self.assertTrue(cerberus_report.service)
        self.assertTrue(cerberus_report.defendant)

        # Try use cache for new request
        report.create_from_email(email_content=content_to_request, send_ack=True)
        cerberus_report = Report.objects.last()
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

        report.cdn_request(
            report_id=cerberus_report.id,
            user_id=user.id,
            domain_to_request='www.cdnproxy-protected-domain.com'
        )

        cerberus_report = Report.objects.last()
        self.assertEqual('Attached', cerberus_report.status)
        self.assertTrue(cerberus_report.service)
        self.assertTrue(cerberus_report.defendant)
