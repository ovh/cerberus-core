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

from abuse.models import (ServiceAction, ContactedProvider, Defendant, Report,
                          Resolution, Stat, Ticket, User)
from adapters.services.phishing.abstract import PingResponse
from factory.factory import ImplementationFactory
from tests import GlobalTestCase

SAMPLES_DIRECTORY = 'tests/samples'


class FakeJob(object):
    """
        Fake rq job for mock
    """
    def __init__(self):
        self.id = 42


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
    def test_report_without_defendant(self, mock_rq):
        """
            Sample1 does not contains any offending items, so just one report and no defendant/service
        """
        from worker import report
        mock_rq.return_value = None
        sample = self._samples['sample1']
        content = sample.read()
        report.create_from_email(email_content=content)
        self.assertEqual(1, Report.objects.count())
        report = Report.objects.all()[:1][0]
        self.assertFalse(report.defendant)
        self.assertFalse(report.service)
        self.assertFalse(report.attachedDocumentRelatedReport.count())
        self.assertFalse(report.reportItemRelatedReport.count())
        self.assertEqual('simon.vasseur@ovh.net', report.provider.email)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_report_with_defendant(self, mock_rq):
        """
            Sample2 contains offending items
        """
        from worker import report
        mock_rq.return_value = None
        sample = self._samples['sample2']
        content = sample.read()
        report.create_from_email(email_content=content)
        self.assertTrue(Defendant.objects.count())
        self.assertEqual(1, Report.objects.count())
        report = Report.objects.all()[:1][0]
        self.assertTrue(report.defendant)
        self.assertEqual('Doe', report.defendant.name)
        self.assertTrue(report.service)
        self.assertFalse(report.ticket)
        self.assertFalse(report.attachedDocumentRelatedReport.count())
        self.assertTrue(report.reportItemRelatedReport.count())
        self.assertIn('213.251.151.160', report.reportItemRelatedReport.all().values_list('rawItem', flat=True))

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_trusted(self, mock_rq):
        """
            Sample6 is a trusted phishing report
        """
        from worker import report
        mock_rq.return_value = None
        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.all()[:1][0]
        self.assertEqual('Phishing', report.category.name)
        self.assertFalse(report.ticket)
        self.assertEqual('PhishToCheck', report.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_not_trusted(self, mock_rq):
        """
            Sample6 is a trusted phishing report
        """
        from worker import report
        mock_rq.return_value = None
        sample = self._samples['sample7']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.all()[:1][0]
        self.assertEqual('Phishing', report.category.name)
        self.assertFalse(report.ticket)
        self.assertEqual('PhishToCheck', report.status)

        # test timeout
        from worker.report import archive_if_timeout
        report.status = 'New'
        report.save()
        archive_if_timeout(report_id=report.id)
        report = Report.objects.get(id=report.id)
        self.assertEqual('Archived', report.status)

    @patch('default.adapters.services.phishing.impl.DefaultPhishingService.ping_url')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_down(self, mock_rq, mock_ping):
        """
            Sample6 is a trusted phishing report, now down items
        """
        from worker import report
        mock_rq.return_value = None
        mock_ping.return_value = PingResponse(100, '404', 'Not Found', 'Not Found')
        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.all()[:1][0]
        self.assertEqual('Phishing', report.category.name)
        self.assertTrue(report.ticket)
        self.assertEqual('Archived', report.status)
        self.assertEqual('Closed', report.ticket.status)
        self.assertEqual(1, ContactedProvider.objects.count())  # Because an email is sent

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_ticket_and_ack(self, mock_rq):
        """
            Sample3 is trusted
        """
        from worker import report
        mock_rq.return_value = None
        sample = self._samples['sample3']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)
        self.assertEqual(1, Report.objects.count())
        report = Report.objects.all()[:1][0]
        self.assertEqual('newsletter@ipm.dhnet.be', report.provider.email)
        self.assertEqual('Copyright', report.category.name)
        self.assertEqual(1, report.ticket.id)
        self.assertEqual('Attached', report.status)

        with ImplementationFactory.instance.get_instance_of('StorageServiceBase', settings.GENERAL_CONFIG['email_storage_dir']) as cnx:
            file_content = cnx.read(report.filename)
            self.assertIn('newsletter@ipm.dhnet.be', file_content)

        emails = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').get_emails(report.ticket)
        self.assertEqual(1, len(emails))
        self.assertEqual(1, ContactedProvider.objects.count())
        self.assertIn(report.ticket.publicId, emails[0].subject)

        # Test stats
        from worker import stats
        stats.update_defendants_history()
        stat = Stat.objects.get(defendant=report.defendant, category='Copyright')
        self.assertEqual(1, stat.reports)
        self.assertEqual(1, stat.tickets)

    @patch('rq_scheduler.scheduler.Scheduler.schedule')
    @patch('default.adapters.services.phishing.impl.DefaultPhishingService.ping_url')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_timeout(self, mock_rq_enqueue, mock_ping, mock_rq_schedule):
        """
            Test phishing workflow
        """
        from worker import report

        mock_rq_enqueue.return_value = None
        mock_ping.return_value = PingResponse(100, '404', 'Not Found', 'Not Found')
        mock_rq_schedule.return_value = FakeJob()

        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        cerberus_report = Report.objects.all()[:1][0]
        cerberus_report.status = 'Attached'
        cerberus_report.ticket.status = 'WaitingAnswer'
        cerberus_report.ticket.snoozeDuration = 1
        cerberus_report.ticket.snoozeStart = datetime.now() - timedelta(days=1)
        cerberus_report.ticket.save()
        cerberus_report.save()

        from worker import workflow

        workflow.follow_the_sun()
        workflow.update_paused()
        workflow.update_waiting()

        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Closed', ticket.status)

    @patch('rq.get_current_job')
    @patch('default.adapters.services.phishing.impl.DefaultPhishingService.ping_url')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_action(self, mock_rq, mock_ping, mock_current_job):
        """
            Test action functions
        """
        from worker import report

        mock_rq.return_value = None
        mock_ping.return_value = PingResponse(100, '404', 'Not Found', 'Not Found')
        mock_current_job.return_value = FakeJob()

        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        cerberus_report = Report.objects.all()[:1][0]
        cerberus_report.status = 'Attached'
        cerberus_report.ticket.status = 'WaitingAnswer'
        cerberus_report.ticket.save()
        cerberus_report.save()

        ip_addr = '8.8.8.8'
        resolution = Resolution.objects.get(codename='fixed')
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])
        service_action = ServiceAction.objects.all()[0]

        from worker import action

        # Success
        action.apply_if_no_reply(
            ticket_id=cerberus_report.ticket.id,
            action_id=service_action.id,
            ip_addr=ip_addr,
            resolution_id=resolution.id,
            user_id=user.id
        )

        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Alarm', ticket.status)

        # Fail
        action.apply_if_no_reply(
            ticket_id=cerberus_report.ticket.id,
            action_id=999999,
            ip_addr=ip_addr,
            resolution_id=resolution.id,
            user_id=user.id
        )

        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('ActionError', ticket.status)

        ticket.status = 'WaitingAnswer'
        ticket.save()

        action.apply_then_close(
            ticket_id=cerberus_report.ticket.id,
            action_id=service_action.id,
            ip_addr=ip_addr,
            resolution_id=resolution.id,
            user_id=user.id
        )
        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Closed', ticket.status)
