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
    Unit tests for tasks functions
"""

import os

from mock import patch

from ...models import Defendant, Report, DefendantHistory, Provider
from ...services.email import EmailService
from ...services.storage import StorageService
from ...tasks.report import create_from_email
from ...tests.setup import CerberusTest


class TestWorkers(CerberusTest):
    """
        Unit tests for workers functions
    """

    def setUp(self):

        super(TestWorkers, self).setUp()
        self._samples = {}

        for root, _, files in os.walk("abuse/tests/samples"):
            for name in files:
                filename = root + "/" + name
                f = open(filename, "r")
                self._samples[name] = f

    def tearDown(self):
        for k, v in self._samples.iteritems():
            v.close()

    @patch("rq_scheduler.scheduler.Scheduler.enqueue_in")
    def test_report_without_defendant(self, mock_rq):
        """
            Sample1 does not contains any offending items,
            so just one report and no defendant/service
        """
        mock_rq.return_value = None
        sample = self._samples["nothing"]
        content = sample.read()
        create_from_email(email_content=content)
        self.assertEqual(1, Report.count())
        report = Report.last()
        self.assertFalse(report.defendant)
        self.assertFalse(report.service)
        self.assertFalse(report.attachments.count())
        self.assertFalse(report.reportItemRelatedReport.count())
        self.assertEqual("me123@ovh.com", report.provider.email)

    @patch("rq_scheduler.scheduler.Scheduler.enqueue_in")
    def test_report_with_defendant(self, mock_rq):
        """
            Sample2 contains offending items
        """
        mock_rq.return_value = None
        sample = self._samples["sample2"]
        content = sample.read()
        create_from_email(email_content=content)
        self.assertTrue(Defendant.count())
        self.assertEqual(1, Report.count())
        report = Report.last()
        self.assertTrue(report.defendant)
        self.assertEqual("Doe", report.defendant.details.name)
        self.assertTrue(report.service)
        self.assertFalse(report.ticket)
        self.assertFalse(report.attachments.count())
        self.assertTrue(report.reportItemRelatedReport.count())
        self.assertIn(
            "213.251.151.160",
            report.reportItemRelatedReport.all().values_list("rawItem", flat=True),
        )

    @patch("rq_scheduler.scheduler.Scheduler.enqueue_in")
    def test_ticket_and_ack(self, mock_rq):
        """
            Assuming Sample3 is trusted
        """
        p, _ = Provider.get_or_create(email="newsletter@ipm.dhnet.be")
        p.trusted = True
        p.save()

        mock_rq.return_value = None
        sample = self._samples["sample3"]
        content = sample.read()
        create_from_email(email_content=content)
        self.assertEqual(1, Report.count())
        report = Report.last()
        self.assertEqual("newsletter@ipm.dhnet.be", report.provider.email)
        self.assertEqual("Copyright", report.category.name)
        self.assertEqual(1, report.ticket.id)
        self.assertEqual("Attached", report.status)

        file_content = StorageService.read(report.filename)
        self.assertIn("newsletter@ipm.dhnet.be", file_content)

        emails = EmailService.get_emails(report.ticket)
        self.assertEqual(1, len(emails))
        self.assertIn(report.ticket.publicId, emails[0].subject)

    @patch("rq_scheduler.scheduler.Scheduler.enqueue_in")
    def test_report_with_attachments(self, mock_rq):
        """
            Sample4 contains attachments
        """
        mock_rq.return_value = None
        sample = self._samples["sample4"]
        content = sample.read()

        with patch(*self.patch_enqueue):
            create_from_email(email_content=content)

        self.assertEqual(1, Report.count())
        cerberus_report = Report.last()

    @patch("rq_scheduler.scheduler.Scheduler.enqueue_in")
    def test_defendant_details_change(self, mock_rq):
        """
            Test defendant revision/history modification
        """
        mock_rq.return_value = None
        sample = self._samples["sample2"]
        content = sample.read()
        create_from_email(email_content=content)
        defendant = Report.last().defendant
        self.assertEqual(1, DefendantHistory.filter(defendant=defendant).count())
        self.assertEqual(1, defendant.details.id)
        defendant.details.name = "Test"
        defendant.details.save()
        defendant.save()
        create_from_email(email_content=content)
        defendant = Report.last().defendant
        self.assertEqual(2, DefendantHistory.filter(defendant=defendant).count())
        self.assertEqual(2, defendant.details.id)
        self.assertEqual("Doe", defendant.details.name)

    @patch("rq_scheduler.scheduler.Scheduler.enqueue_in")
    def test_ticket_change_priority(self, mock_rq):
        """
            Test if ticket is actually changing priority
        """
        for prio in ("low", "normal", "critical"):
            p, _ = Provider.get_or_create(email="{}@provider.com".format(prio))
            p.trusted = True
            p.save()

        mock_rq.return_value = None

        sample = self._samples["sample11"]  # Low
        content = sample.read()
        create_from_email(email_content=content)
        cerberus_report_1 = Report.last()
        self.assertEqual("Low", cerberus_report_1.ticket.priority)

        sample = self._samples["sample13"]  # Critical
        content = sample.read()
        create_from_email(email_content=content)
        cerberus_report_2 = Report.last()
        self.assertEqual(cerberus_report_1.ticket.id, cerberus_report_2.ticket.id)
        self.assertEqual("Critical", cerberus_report_2.ticket.priority)

        sample = self._samples["sample12"]  # Normal
        content = sample.read()
        create_from_email(email_content=content)
        cerberus_report_3 = Report.last()
        self.assertEqual(cerberus_report_1.ticket.id, cerberus_report_3.ticket.id)
        self.assertEqual("Critical", cerberus_report_3.ticket.priority)

    @patch("rq_scheduler.scheduler.Scheduler.enqueue_in")
    def test_blacklisted_provider(self, mock_rq):
        """
            Test if ticket is actually changing priority
        """
        mock_rq.return_value = None

        sample = self._samples["sample14"]  # Blacklisted
        content = sample.read()
        create_from_email(email_content=content)
        self.assertEqual(0, Report.count())

    @patch("rq_scheduler.scheduler.Scheduler.enqueue_in")
    def test_report_new(self, mock_rq):
        """
            Check that report's status is 'New'
            when no services identified
        """
        mock_rq.return_value = None

        sample = self._samples["sample22"]
        content = sample.read()
        create_from_email(email_content=content)
        cerberus_report = Report.last()
        self.assertEqual("New", cerberus_report.status)

    @patch("rq_scheduler.scheduler.Scheduler.enqueue_in")
    def test_report_tovalidate(self, mock_rq):
        """
            Check that report's status is 'ToValidate'
            when trusted but no services identified
        """
        p, _ = Provider.get_or_create(email="aze@provider.com")
        p.trusted = True
        p.save()

        mock_rq.return_value = None

        sample = self._samples["sample21"]  # Low
        content = sample.read()
        create_from_email(email_content=content)
        cerberus_report = Report.last()
        self.assertEqual("ToValidate", cerberus_report.status)
