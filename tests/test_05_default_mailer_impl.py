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
    Unit tests for mailer service default implementation
"""

from datetime import datetime

from django.test import TestCase

from abuse.models import MailTemplate, Ticket
from adapters.services.mailer.abstract import MailerServiceException
from default.adapters.services.mailer.impl import DefaultMailerService


class GlobalTestCase(TestCase):
    """
        Global setUp for tests
    """
    def setUp(self):
        self._ticket = Ticket.objects.create(
            publicId='AAAAAAAAAA',
            category_id='Spam',
            creationDate=datetime.now(),
        )
        MailTemplate.objects.create(
            codename='default_template',
            name='Default template',
            subject='Abuse dectected, Ticket #{{ publicId }}',
            body='Abuse dectected, Ticket #{{ publicId }}',
        )
        self._impl = DefaultMailerService()

    def tearDown(self):
        pass


class TestDefaultMailerImpl(GlobalTestCase):
    """
        Unit tests for mailer service
    """
    def test_send_get_email(self):
        """
            Test send_email and get_emails
        """
        self._impl.send_email(self._ticket, 'test@test.com', 'test', 'test')
        self._impl.send_email(self._ticket, 'test@test.com', 'test', 'test')
        emails = self._impl.get_emails(self._ticket)
        self.assertEqual(2, len(emails))
        self._ticket.publicId = 'BBBBBBBBBB'
        self.assertRaises(MailerServiceException, lambda: self._impl.get_emails(self._ticket))
        self.assertRaises(MailerServiceException, lambda: self._impl.send_email(self._ticket, 'test', 'test', 'test'))

    def test_attach_external_answer(self):
        """
            Test attach_external_answer
        """
        self._impl.send_email(self._ticket, 'test@test.com', 'test', 'test')
        self._impl.attach_external_answer(self._ticket, 'test123@site.com', 'Re: test', 'Answer test')
        emails = self._impl.get_emails(self._ticket)
        self.assertEqual(4, len(emails))
        self.assertRaises(MailerServiceException, lambda: self._impl.attach_external_answer(123456, 'test', 'test', 'test'))

    def test_prefetch_template(self):
        """
            Test prefetch_template
        """
        prefetched_email = self._impl.prefetch_email_from_template(self._ticket, 'default_template')
        self.assertIn(self._ticket.publicId, prefetched_email.subject)
        self.assertIn(self._ticket.publicId, prefetched_email.body)
        self.assertRaises(MailerServiceException, lambda: self._impl.prefetch_email_from_template(123456, 'default_template'))
        self.assertRaises(MailerServiceException, lambda: self._impl.prefetch_email_from_template(self._ticket, 'invalid_template'))
