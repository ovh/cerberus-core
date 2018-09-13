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
    Unit tests for threshold workflow
"""

import os

from datetime import datetime
from mock import patch

from ...models import (Report, BusinessRulesHistory,
                       ReportThreshold, Ticket)
from ...tasks.report import create_from_email
from ...tests.setup import CerberusTest


class TestThreshold(CerberusTest):
    """
        Unit tests for workers functions
    """
    def setUp(self):

        super(TestThreshold, self).setUp()
        self._samples = {}

        for root, dirs, files in os.walk('abuse/tests/samples'):
            for name in files:
                filename = root + '/' + name
                f = open(filename, 'r')
                self._samples[name] = f

    def tearDown(self):
        for k, v in self._samples.iteritems():
            v.close()

    def test_report_threshold(self):
        """
        """
        sample = self._samples['sample2']
        content = sample.read()
        content = content.replace(
            '29 Apr 2015',
            datetime.now().strftime('%d %b %Y')
        )
        ReportThreshold.objects.all().update(threshold=3, interval=86400)

        with patch(*self.patch_enqueue_in):
            for _ in xrange(2):
                create_from_email(email_content=content)
                cerberus_report = Report.objects.last()
                self.assertEqual('New', cerberus_report.status)

        create_from_email(email_content=content)
        cerberus_report = Report.objects.last()
        self.assertEqual('Attached', cerberus_report.status)

        tickets = Ticket.objects.filter(
            defendant=cerberus_report.defendant,
            category=cerberus_report.category,
            service=cerberus_report.service
        ).count()

        self.assertEqual(1, tickets)

        history = BusinessRulesHistory.objects.filter(
            businessRules__name='default_defendant_threshold'
        ).count()
        self.assertEqual(1, history)

        history = BusinessRulesHistory.objects.filter(
            businessRules__name='default_defendant_not_trusted_no_ticket'
        ).count()
        self.assertEqual(2, history)
