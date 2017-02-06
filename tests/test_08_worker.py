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

from django.conf import settings
from mock import patch

from abuse.models import (ContactedProvider, Defendant, Report, User,
                          ReportThreshold, DefendantHistory)
from factory.implementation import ImplementationFactory
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
        report = Report.objects.last()
        self.assertFalse(report.defendant)
        self.assertFalse(report.service)
        self.assertFalse(report.attachments.count())
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
        report = Report.objects.last()
        self.assertTrue(report.defendant)
        self.assertEqual('Doe', report.defendant.details.name)
        self.assertTrue(report.service)
        self.assertFalse(report.ticket)
        self.assertFalse(report.attachments.count())
        self.assertTrue(report.reportItemRelatedReport.count())
        self.assertIn('213.251.151.160', report.reportItemRelatedReport.all().values_list('rawItem', flat=True))

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
        report = Report.objects.last()
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

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_report_with_attachments(self, mock_rq):
        """
            Sample4 contains attachments
        """
        from worker import report

        mock_rq.return_value = None
        sample = self._samples['sample4']
        content = sample.read()
        report.create_from_email(email_content=content)
        self.assertEqual(1, Report.objects.count())
        cerberus_report = Report.objects.last()
        self.assertEqual(2, cerberus_report.attachments.count())

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_defendant_details_change(self, mock_rq):
        """
            Test defendant revision/history modification
        """
        from worker import report

        mock_rq.return_value = None
        sample = self._samples['sample2']
        content = sample.read()
        report.create_from_email(email_content=content)
        defendant = Report.objects.last().defendant
        self.assertEqual(1, DefendantHistory.objects.filter(defendant=defendant).count())
        self.assertEqual(1, defendant.details.id)
        defendant.details.name = 'Test'
        defendant.details.save()
        defendant.save()
        report.create_from_email(email_content=content)
        defendant = Report.objects.last().defendant
        self.assertEqual(2, DefendantHistory.objects.filter(defendant=defendant).count())
        self.assertEqual(2, defendant.details.id)
        self.assertEqual('Doe', defendant.details.name)

    @patch('rq.queue.Queue.enqueue')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_ticket_from_phishtocheck(self, mock_rq, mock_rq_enqueue):

        from worker import report, ticket

        mock_rq.return_value = None
        mock_rq_enqueue.return_value = FakeJob()
        sample = self._samples['sample7']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        cerberus_report = Report.objects.last()
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])
        ticket.create_ticket_from_phishtocheck(report=cerberus_report.id, user=user.id)
        cerberus_report = Report.objects.last()
        self.assertEqual('Attached', cerberus_report.status)
        self.assertEqual(1, cerberus_report.ticket.id)
        emails = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').get_emails(cerberus_report.ticket)
        self.assertEqual(1, len(emails))

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_ticket_change_priority(self, mock_rq):
        """
            Test if ticket is actually changing priority
        """
        from worker import report

        mock_rq.return_value = None

        sample = self._samples['sample11']  # Low
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)
        cerberus_report_1 = Report.objects.last()
        self.assertEqual('Low', cerberus_report_1.ticket.priority)

        sample = self._samples['sample13']  # Critical
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)
        cerberus_report_2 = Report.objects.last()
        self.assertEqual(cerberus_report_1.ticket.id, cerberus_report_2.ticket.id)
        self.assertEqual('Critical', cerberus_report_2.ticket.priority)

        sample = self._samples['sample12']  # Normal
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)
        cerberus_report_3 = Report.objects.last()
        self.assertEqual(cerberus_report_1.ticket.id, cerberus_report_3.ticket.id)
        self.assertEqual('Critical', cerberus_report_3.ticket.priority)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_blacklisted_provider(self, mock_rq):
        """
            Test if ticket is actually changing priority
        """
        from worker import report

        mock_rq.return_value = None

        sample = self._samples['sample14']  # Blacklisted
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)
        self.assertEqual(0, Report.objects.count())

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_report_new(self, mock_rq):
        """
            Check that report's status is 'New' when no services identified
        """
        from worker import report

        mock_rq.return_value = None

        sample = self._samples['sample22']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)
        cerberus_report = Report.objects.last()
        self.assertEqual('New', cerberus_report.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_report_tovalidate(self, mock_rq):
        """
            Check that report's status is 'ToValidate' when trusted but no services identified
        """
        from worker import report

        mock_rq.return_value = None

        sample = self._samples['sample21']  # Low
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)
        cerberus_report = Report.objects.last()
        self.assertEqual('ToValidate', cerberus_report.status)
