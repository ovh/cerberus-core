# -*- coding: utf8 -*-
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
    Default Mailer Service Implementation
"""

import hashlib
import os
import re
import sqlite3
from time import time

import html2text
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models import ObjectDoesNotExist
from django.template import (Context, TemplateEncodingError,
                             TemplateSyntaxError, loader)

from abuse.models import ContactedProvider, MailTemplate, Provider, Ticket
from adapters.services.mailer.abstract import (Email, MailerServiceBase,
                                               MailerServiceException,
                                               PrefetchedEmail)

html2text.ignore_images = True
html2text.images_to_alt = True
html2text.ignore_links = True

CERBERUS_EMAIL_DB = settings.GENERAL_CONFIG['cerberus_emails_db']


class TemplateNeedProofError(Exception):
    """
        TemplateNeedProofError
    """
    def __init__(self, message):
        super(TemplateNeedProofError, self).__init__(message)


class DefaultMailerService(MailerServiceBase):
    """
        Handling basic mailer interactions. Store emails in a naive sqlite DB.

        For this default implementation, emails are not send. You can easily fill the method send_email_with_backend()
    """
    def __init__(self):
        """
        """
        try:
            directory = settings.GENERAL_CONFIG['email_storage_dir']
            if not os.path.exists(directory):
                os.makedirs(directory)
        except Exception as ex:
            raise MailerServiceException(ex)

        self._db_conn = sqlite3.connect(directory + '/' + CERBERUS_EMAIL_DB)
        cursor = self._db_conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS emails
                (publicid text, sender text, recipient text, subject text, body text, timestamp int)''')
        self._db_conn.commit()

        self._html_parser = html2text.HTML2Text()
        self._html_parser.body_width = 0

    def send_email(self, ticket, recipient, subject, body, sender=None):
        """
            Send a email.

            If you send links to phishing screenshots, could be interesting to store sent
            links (screenshotId from PhishinServiceBase.get_screenshots()) in ItemScreenshotFeedback

            :param 'abuse.models.Ticket` ticket: A Cerberus 'abuse.models.Ticket` instance.
            :param str recipient: The recipient of the email
            :param str subject: The subject of the email
            :param str body: The body of the email
            :param str sender: Eventually the sender of the email (From)
            :raises `adapters.services.mailer.abstract.MailerServiceException`: if any error occur
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.objects.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise MailerServiceException('Ticket %s cannot be found in DB. Skipping...' % (str(ticket)))
        try:
            validate_email(recipient.strip())
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise MailerServiceException('Invalid email')

        # Save contacted provider
        ticket_providers = list(set(ticket.reportTicket.all().values_list('provider__email', flat=True).distinct()))
        if recipient in ticket_providers:
            provider = Provider.objects.get(email=recipient)
            if not ticket.contactedProviders.filter(provider__email=recipient).exists():
                ContactedProvider.objects.create(ticket=ticket, provider=provider)

        hsh = hashlib.sha512(str(ticket.id)).hexdigest()[-4:]
        sender = settings.EMAIL_FETCHER['cerberus_email'] % (ticket.publicId, hsh) if not sender else sender
        self.__update_emails_db(ticket.publicId, sender, recipient, subject, body, int(time()))

        # You cans fill this method
        send_email_with_backend()

    def get_emails(self, ticket):
        """
            Get all emails for the given ticket

            :param 'abuse.models.Ticket` ticket: A Cerberus 'abuse.models.Ticket` instance.
            :return: A list of Email object
            :rtype: list
            :raises `adapters.services.mailer.abstract.MailerServiceException`: if any error occur
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.objects.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise MailerServiceException('Ticket %s cannot be found in DB. Skipping...' % (str(ticket)))

        self.__check_ticket_emails(ticket)

        cursor = self._db_conn.cursor()
        param = (ticket.publicId,)
        emails = []
        try:
            for row in cursor.execute('SELECT sender, recipient, subject, body, timestamp FROM emails WHERE publicid=?', param):
                body = self._html_parser.handle(row[3].replace('<br>\n', '\n').replace('\n', '<br>\n'))
                emails.append(Email(
                    sender=row[0],
                    recipient=row[1],
                    subject=row[2],
                    body=re.sub(r'^(\s*\n){2,}', '\n', body, flags=re.MULTILINE),
                    created=row[4],
                ))
        except (KeyError, ValueError) as ex:
            raise MailerServiceException(ex)

        emails = sorted(emails, key=lambda k: k.created)
        return emails

    def attach_external_answer(self, ticket, sender, subject, body):
        """
            Can be usefull if an answer for a ticket come from Phone/CRM/API/CustomerUX ...

            :param 'abuse.models.Ticket` ticket: A Cerberus 'abuse.models.Ticket` instance.
            :param str sender: The sender of the email
            :param str subject: The subject of the email
            :param str body: The body of the email
            :raises `adapters.services.mailer.abstract.MailerServiceException`: if any error occur
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.objects.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise MailerServiceException('Ticket %s cannot be found in DB. Skipping...' % (str(ticket)))

        self.__check_ticket_emails(ticket)
        recipient = settings.EMAIL_FETCHER['cerberus_email'] % (ticket.publicId, 'test', 'test') if not sender else sender
        self.__update_emails_db(ticket.publicId, sender, recipient, subject, body, int(time()))

    def prefetch_email_from_template(self, ticket, template_codename, lang='EN', acknowledged_report=None):
        """
            Try to fill email template with ticket meta

            :param 'abuse.models.Ticket` ticket: A Cerberus 'abuse.models.Ticket` instance.
            :param str template_codename: The codename of the template
            :param str lang: The langage to use
            :param int acknowledged_report: Eventually add a report body to the email body (in case of acknowledgment)
            :return: The prefetched email
            :rtype: `adapters.services.mailer.abstract.PrefetchedEmail`
            :raises `adapters.services.mailer.abstract.MailerServiceException`: if any error occur
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.objects.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise MailerServiceException('Ticket %s cannot be found in DB. Skipping...' % (str(ticket)))
        try:
            mail_template = MailTemplate.objects.get(codename=template_codename)
        except (ObjectDoesNotExist, ValueError):
            raise MailerServiceException('Email template %s can not be found in DB. Skipping...' % (template_codename))

        try:
            template = loader.get_template_from_string(mail_template.subject)
            context = Context({
                'publicId': ticket.publicId,
            })
            subject = template.render(context)
            template = loader.get_template_from_string(mail_template.body)
            context = Context({
                'publicId': ticket.publicId,
            })
            body = template.render(context)
        except (TemplateEncodingError, TemplateSyntaxError):
            raise MailerServiceException('Error while generating template')

        return PrefetchedEmail(
            sender=None,
            recipients=['test@example.com'],
            subject=subject,
            body=body,
        )

    def close_thread(self, ticket):
        """
            Close thread

            :param 'abuse.models.Ticket` ticket: A Cerberus 'abuse.models.Ticket` instance.
        """
        pass

    def __check_ticket_emails(self, ticket):
        """
            check if emails exist for given ticket

            :raises `adapters.services.mailer.abstract.MailerServiceException`: if no emails are found
        """
        cursor = self._db_conn.cursor()
        param = (ticket.publicId,)
        cursor.execute('SELECT COUNT(*) FROM emails WHERE publicid=?', param)
        if not cursor.fetchone()[0]:
            raise MailerServiceException('No emails found for this ticket')

    def __update_emails_db(self, public_id, sender, recipient, subject, body, timestamp):
        """
            Insert emails infos in db
        """
        data = (public_id, sender, recipient, subject, body, timestamp,)
        cursor = self._db_conn.cursor()
        cursor.execute('INSERT INTO emails VALUES (?,?,?,?,?,?)', data)
        self._db_conn.commit()


def send_email_with_backend():
    """
        Send an email using SMTP/API or other backend
    """
    pass
