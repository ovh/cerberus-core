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

from ...models import MailTemplate, Ticket
from ...services.email import EmailService
from ...services.email.base import EmailServiceException
from ...tests.setup import CerberusTest


class TestDefaultMailerImpl(CerberusTest):
    """
        Unit tests for mailer service
    """
    def setUp(self):

        self._ticket = Ticket.create(
            publicId='AAAAAAAAAA',
            category_id='Spam',
            creationDate=datetime.now(),
        )
        MailTemplate.create(
            codename='default_template',
            name='Default template',
            subject='Abuse dectected, Ticket #{{ publicId }}',
            body='Abuse dectected, Ticket #{{ publicId }}',
            recipientType='Defendant',
        )

    def test_01_send_get_email(self):
        """
            Test send_email and get_emails
        """
        EmailService.send_email(self._ticket, 'test@test.com', 'test', 'test', 'Defendant')
        EmailService.send_email(self._ticket, 'test@test.com', 'test', 'test', 'Other')
        emails = EmailService.get_emails(self._ticket)
        self.assertEqual(2, len(emails))
        self.assertRaises(EmailServiceException, lambda: EmailService.send_email(self._ticket, 'test@test.com', 'test', 'test', 'InvalidCategory'))
        self._ticket.publicId = 'ZZZZZZZZZZ'
        self.assertRaises(EmailServiceException, lambda: EmailService.get_emails(self._ticket))
        self.assertRaises(EmailServiceException, lambda: EmailService.send_email(self._ticket, 'test', 'test', 'test', 'Defendant'))

    def test_02_attach_external_answer(self):
        """
            Test attach_external_answer
        """
        recipient = 'ticket+AAAAAAAAAA.defendant@example.com'
        EmailService.send_email(self._ticket, 'test@test.com', 'test', 'test', 'Defendant')
        EmailService.attach_external_answer(
            self._ticket,
            'test123@site.com',
            recipient,
            'Re: test',
            'Answer test',
            'Defendant'
        )
        emails = EmailService.get_emails(self._ticket)
        self.assertEqual(4, len(emails))
        self.assertRaises(EmailServiceException, lambda: EmailService.attach_external_answer(123456, 'test', recipient, 'test', 'test', 'Defendant'))

    def test_prefetch_template(self):
        """
            Test prefetch_template
        """
        prefetched_email = EmailService.prefetch_email_from_template(self._ticket, 'default_template')
        self.assertIn(self._ticket.publicId, prefetched_email.subject)
        self.assertIn(self._ticket.publicId, prefetched_email.body)
        self.assertEqual('Defendant', prefetched_email.category)
        self.assertRaises(EmailServiceException, lambda: EmailService.prefetch_email_from_template(123456, 'default_template'))
        self.assertRaises(EmailServiceException, lambda: EmailService.prefetch_email_from_template(self._ticket, 'invalid_template'))
