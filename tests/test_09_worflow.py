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

from abuse.models import (ServiceAction, ContactedProvider, Report, Provider,
                          Resolution, Ticket, User, UrlStatus)
from adapters.services.phishing.abstract import PingResponse
from factory.factory import ImplementationFactory, ReportWorkflowHookFactory
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
    def test_phishing_report_trusted(self, mock_rq):
        """
            Sample6 is a phishing report
        """
        ReportWorkflowHookFactory.instance.read_hooks_available()
        from worker import report

        mock_rq.return_value = None
        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.last()
        self.assertEqual('Phishing', report.category.name)
        self.assertFalse(report.ticket)
        self.assertEqual('PhishToCheck', report.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_not_trusted(self, mock_rq):
        """
            Sample7 is a phishing report
        """
        ReportWorkflowHookFactory.instance.read_hooks_available()
        from worker import report

        mock_rq.return_value = None
        sample = self._samples['sample7']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.last()
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
            Sample6 is a phishing report, now down items
        """
        ReportWorkflowHookFactory.instance.read_hooks_available()
        from worker import report

        mock_rq.return_value = None
        mock_ping.return_value = PingResponse(100, '404', 'Not Found', 'Not Found', False)
        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.last()
        self.assertEqual('Phishing', report.category.name)
        self.assertTrue(report.ticket)
        self.assertEqual('Archived', report.status)
        self.assertEqual('Closed', report.ticket.status)
        self.assertEqual(1, ContactedProvider.objects.count())  # Because an email is sent

    @patch('rq.queue.Queue.enqueue')
    @patch('rq_scheduler.scheduler.Scheduler.schedule')
    @patch('default.adapters.services.phishing.impl.DefaultPhishingService.ping_url')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_timeout(self, mock_rq_enqueue_in, mock_ping, mock_rq_schedule, mock_rq_enqueue):
        """
            Test phishing workflow
        """
        ReportWorkflowHookFactory.instance.read_hooks_available()
        from worker import report

        mock_rq_enqueue_in.return_value = None
        mock_ping.return_value = PingResponse(100, '404', 'Not Found', 'Not Found for test_phishing_timeout', False)
        mock_rq_schedule.return_value = FakeJob()
        mock_rq_enqueue.return_value = FakeJob()

        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        # Reopening ticket
        cerberus_report = Report.objects.last()
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
        self.assertEqual(settings.CODENAMES['fixed_customer'], ticket.resolution.codename)

        # Reopening ticket
        UrlStatus.objects.all().delete()
        mock_ping.return_value = PingResponse(0, '200', 'UP', 'UP for test_phishing_timeout', False)
        cerberus_report = Report.objects.last()
        cerberus_report.status = 'Attached'
        cerberus_report.ticket.status = 'WaitingAnswer'
        cerberus_report.ticket.snoozeDuration = 1
        cerberus_report.ticket.snoozeStart = datetime.now() - timedelta(days=1)
        cerberus_report.ticket.save()
        cerberus_report.save()

        ticket_func.update_waiting()

        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Alarm', ticket.status)
        ticket_func.timeout(ticket.id)
        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Closed', ticket.status)
        self.assertEqual(settings.CODENAMES['fixed'], ticket.resolution.codename)

    @patch('rq.queue.Queue.enqueue')
    @patch('rq_scheduler.scheduler.Scheduler.schedule')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_copyright_specific_workflow(self, mock_rq_enqueue_in, mock_rq_schedule, mock_rq_enqueue):
        """
            Test copyright timeout
        """
        ReportWorkflowHookFactory.instance.read_hooks_available()
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
        self.assertIn('report:copyright_workflow_hook', cerberus_report.tags.all().values_list('name', flat=True))

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

    @patch('rq.get_current_job')
    @patch('default.adapters.services.phishing.impl.DefaultPhishingService.ping_url')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_action(self, mock_rq, mock_ping, mock_current_job):
        """
            Test action functions
        """
        ReportWorkflowHookFactory.instance.read_hooks_available()
        from worker import report

        mock_rq.return_value = None
        mock_ping.return_value = PingResponse(100, '404', 'Not Found', 'Not Found', False)
        mock_current_job.return_value = FakeJob()

        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        cerberus_report = Report.objects.last()
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

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_acns_specific_workflow(self, mock_rq):
        """
            Test copyright/acns specific workflow
        """
        ReportWorkflowHookFactory.instance.read_hooks_available()
        from worker import report

        Provider.objects.create(email='broadgreenpictures@copyright-compliance.com', trusted=True)
        mock_rq.return_value = None
        sample = self._samples['acns']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()

        emails = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').get_emails(cerberus_report.ticket)
        self.assertEqual(2, len(emails))
        self.assertEqual('Archived', cerberus_report.status)
        self.assertEqual('Closed', cerberus_report.ticket.status)

    # Now testing without specific workflow
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_trusted_no_workflow(self, mock_rq):
        """
            Sample6 is a trusted phishing report
        """
        ReportWorkflowHookFactory.instance.registered_hook_instances = []
        from worker import report

        mock_rq.return_value = None
        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.last()
        self.assertEqual('Phishing', report.category.name)
        self.assertTrue(report.ticket)
        self.assertEqual('Attached', report.status)
        self.assertEqual('Open', report.ticket.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_not_trusted_no_workflow(self, mock_rq):
        """
            Sample7 is not a trusted phishing report
        """
        ReportWorkflowHookFactory.instance.registered_hook_instances = []
        from worker import report

        mock_rq.return_value = None
        sample = self._samples['sample7']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.last()
        self.assertEqual('Phishing', report.category.name)
        self.assertFalse(report.ticket)
        self.assertEqual('New', report.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_acns_specific_no_workflow(self, mock_rq):
        """
            Test copyright/acns specific workflow
        """
        ReportWorkflowHookFactory.instance.registered_hook_instances = []
        from worker import report

        Provider.objects.create(email='broadgreenpictures@copyright-compliance.com', trusted=True)
        mock_rq.return_value = None
        sample = self._samples['acns']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()

        self.assertEqual('Attached', cerberus_report.status)
        self.assertEqual('Open', cerberus_report.ticket.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_acns_specific_no_workflow_2(self, mock_rq):
        """
            Test copyright/acns specific workflow
        """
        ReportWorkflowHookFactory.instance.registered_hook_instances = []
        from worker import report

        Provider.objects.create(email='broadgreenpictures@copyright-compliance.com', trusted=False)
        mock_rq.return_value = None
        sample = self._samples['acns']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()

        self.assertEqual('New', cerberus_report.status)
        self.assertFalse(cerberus_report.ticket)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_trusted_provider(self, mock_rq):
        """
            Sample20 came from a trusted phishing provider
        """
        ReportWorkflowHookFactory.instance.read_hooks_available()
        from worker import report

        mock_rq.return_value = None
        sample = self._samples['sample20']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        cerberus_report = Report.objects.last()
        self.assertEqual('Phishing', cerberus_report.category.name)
        self.assertTrue(cerberus_report.ticket)
        self.assertEqual('Attached', cerberus_report.status)

        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        cerberus_report = Report.objects.last()
        self.assertEqual('Phishing', cerberus_report.category.name)
        self.assertFalse(cerberus_report.ticket)
        self.assertEqual('PhishToCheck', cerberus_report.status)

        sample = self._samples['sample7']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        cerberus_report = Report.objects.last()
        self.assertEqual('Phishing', cerberus_report.category.name)
        self.assertFalse(cerberus_report.ticket)
        self.assertEqual('PhishToCheck', cerberus_report.status)

    @patch('rq.queue.Queue.enqueue')
    @patch('rq_scheduler.scheduler.Scheduler.schedule')
    @patch('default.adapters.services.phishing.impl.DefaultPhishingService.ping_url')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_clearly_identified_phishing(self, mock_rq_enqueue_in, mock_ping, mock_rq_schedule, mock_rq_enqueue):
        """
            Test when phishing is clearly identified (PingResponse last parameter is True)
        """
        ReportWorkflowHookFactory.instance.read_hooks_available()
        from worker import report

        mock_rq_enqueue_in.return_value = None
        mock_ping.return_value = PingResponse(0, '200', 'OK', 'OK', True)
        mock_rq_schedule.return_value = FakeJob()
        mock_rq_enqueue.return_value = FakeJob()

        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)

        cerberus_report = Report.objects.last()
        self.assertEqual('Phishing', cerberus_report.category.name)
        self.assertTrue(cerberus_report.ticket)
        self.assertEqual('WaitingAnswer', cerberus_report.ticket.status)
        self.assertEqual('Attached', cerberus_report.status)
        emails = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').get_emails(cerberus_report.ticket)
        self.assertEqual(2, len(emails))
        email = emails[0]
        self.assertIn('http://www.example.com/phishing.html', email.body)
