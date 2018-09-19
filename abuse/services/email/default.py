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

import os
import random
import re
import sqlite3

from time import time

import html2text
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models import ObjectDoesNotExist
from django.template.base import TemplateEncodingError
from django.template import engines, TemplateSyntaxError

from .base import (
    EMAIL_VALID_CATEGORIES,
    Email,
    EmailServiceBase,
    EmailServiceException,
    PrefetchedEmail,
)
from ...models import MailTemplate, Ticket

django_template_engine = engines["django"]

html2text.ignore_images = True
html2text.images_to_alt = True
html2text.ignore_links = True


class TemplateNeedProofError(Exception):
    """
        TemplateNeedProofError
    """

    def __init__(self, message):
        super(TemplateNeedProofError, self).__init__(message)


class DefaultMailerService(EmailServiceBase):
    """
        Handling basic mailer interactions. Store emails in a naive sqlite DB.

        For this example implementation, emails are not send.
    """

    def __init__(self, config, logger=None):

        try:
            directory = config["directory"]
            if not os.path.exists(directory):
                os.makedirs(directory)
        except Exception as ex:
            raise EmailServiceException(ex)

        self._db_conn = sqlite3.connect(directory + "/cerberus_emails_test.db")
        cursor = self._db_conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS emails
                (publicid text, sender text, recipient text, subject text, body text, category text, timestamp int)"""
        )
        self._db_conn.commit()

        self._html_parser = html2text.HTML2Text()
        self._html_parser.body_width = 0
        self._sender_email = "ticket+{}.{}@example.com"
        self._sender_re = re.compile(r"ticket\+(\w+).(\w+)@example.com", re.I)

    def send_email(
        self, ticket, recipient, subject, body, category, sender=None, attachments=None
    ):
        """
            Send a email.

            If you send links to phishing screenshots,
            could be interesting to store sent
            links (screenshotId from PhishinServiceBase.get_screenshots())
            in ItemScreenshotFeedback

            :param `abuse.models.Ticket` ticket: A ticket instance
            :param str recipient: The recipient of the email
            :param str subject: The subject of the email
            :param str body: The body of the email
            :param str category: `cerberus.services.email.base.EMAIL_VALID_CATEGORIES`
            :param str sender: Eventually the sender of the email (From)
            :param list attachments
            :raises `cerberus.services.email.base.EmailServiceException`
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise EmailServiceException("Ticket {} not be found".format(ticket))
        try:
            validate_email(recipient.strip())
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise EmailServiceException("Invalid email")

        if category:
            category = category.title()
            if category not in EMAIL_VALID_CATEGORIES:
                raise EmailServiceException(
                    "Invalid email category {}".format(category)
                )

        sender = sender or self._sender_email.format(ticket.publicId, category)
        self._update_emails_db(
            ticket.publicId, sender, recipient, subject, body, category, int(time())
        )

        # You can fill this method
        send_email_with_backend(ticket)

    def get_emails(self, ticket):
        """
            Get all emails for the given ticket

            :param `abuse.models.Ticket` ticket: A ticket instance
            :return: A list of Email object
            :rtype: list
            :raises `cerberus.services.email.base.EmailServiceException`
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise EmailServiceException("Ticket {} not be found".format(ticket))

        self._check_ticket_emails(ticket)

        cursor = self._db_conn.cursor()
        param = (ticket.publicId,)
        emails = []
        try:
            query = cursor.execute(
                "SELECT sender, recipient, subject, body, category, timestamp FROM emails WHERE publicid=?",
                param,
            )
            for row in query:
                body = self._html_parser.handle(
                    row[3].replace("<br>\n", "\n").replace("\n", "<br>\n")
                )
                emails.append(
                    Email(
                        sender=row[0],
                        recipient=row[1],
                        subject=row[2],
                        body=re.sub(r"^(\s*\n){2,}", "\n", body, flags=re.MULTILINE),
                        category=row[4],
                        created=row[5],
                        attachments=[],
                    )
                )
        except (KeyError, ValueError) as ex:
            raise EmailServiceException(ex)

        emails = sorted(emails, key=lambda k: k.created)
        return emails

    def attach_external_answer(
        self, ticket, sender, recipient, subject, body, category, attachments=None
    ):
        """
            Can be usefull if an answer for a ticket come
            from Phone/CRM/API/CustomerUX ...

            :param `abuse.models.Ticket` ticket: A ticket instance
            :param str sender: The sender of the email
            :param str recipient: The recipient of the answer
            :param str subject: The subject of the email
            :param str body: The body of the email
            :param str category: `cerberus.services.email.base.EMAIL_VALID_CATEGORIES`
            :param list attachments: `cerberus.parsers.ParsedEmail` attachments
            :raises `cerberus.services.email.base.EmailServiceException`
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise EmailServiceException("Ticket {} not be found".format(ticket))

        if category:
            category = category.title()
            if category not in EMAIL_VALID_CATEGORIES:
                raise EmailServiceException(
                    "Invalid email category {}".format(category)
                )

        self._check_ticket_emails(ticket)
        self._update_emails_db(
            ticket.publicId, sender, recipient, subject, body, category, int(time())
        )

    def is_email_ticket_answer(self, email):
        """
            Returns if the email is an answer to a `abuse.models.Ticket`

            :param `cerberus.parsers.ParsedEmail` email: The parsed email
            :return: a list of tuple (
                `abuse.models.Ticket`,
                `cerberus.services.email.base.EMAIL_VALID_CATEGORIES`,
                recipient
            )
            :rtype: list
        """
        tickets = []
        if all((email.provider, email.recipients, email.subject, email.body)):
            tickets = self._identify_ticket_from_meta(
                email.provider, email.recipients, email.subject
            )
        return tickets

    @staticmethod
    def prefetch_email_from_template(
        ticket, template_codename, lang="EN", acknowledged_report=None
    ):
        """
            Try to fill email template with ticket meta

            :param `abuse.models.Ticket` ticket: A ticket instance
            :param str template_codename: The codename of the template
            :param str lang: The langage to use
            :param int acknowledged_report: Eventually add a report body to
                                            the email body
                                            (in case of acknowledgment)
            :return: The prefetched email
            :rtype: `cerberus.services.email.base.PrefetchedEmail`
            :raises `cerberus.services.email.base.EmailServiceException
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise EmailServiceException("Ticket {} not be found".format(ticket))
        try:
            mail_template = MailTemplate.get(codename=template_codename)
        except (ObjectDoesNotExist, ValueError):
            raise EmailServiceException(
                "Email template {} not found".format(template_codename)
            )

        try:
            subject = generate_subject(ticket, mail_template)
            body = generate_body(ticket, mail_template)
        except (TemplateEncodingError, TemplateSyntaxError):
            raise EmailServiceException("Error while generating template")

        return PrefetchedEmail(
            sender=None,
            recipients=["test@example.com"],
            subject=subject,
            body=body,
            category=mail_template.recipientType,
        )

    def close_thread(self, ticket):
        """
            Close thread

            :param `abuse.models.Ticket` ticket: A ticket instance
        """
        pass

    def _check_ticket_emails(self, ticket):
        """
            check if emails exist for given ticket

            :raises `cerberus.services.email.base.EmailServiceException`
        """
        cursor = self._db_conn.cursor()
        param = (ticket.publicId,)
        cursor.execute("SELECT COUNT(*) FROM emails WHERE publicid=?", param)
        if not cursor.fetchone()[0]:
            raise EmailServiceException("No emails found for this ticket")

    def _update_emails_db(
        self, public_id, sender, recipient, subject, body, category, timestamp
    ):
        """
            Insert emails infos in db
        """
        data = (public_id, sender, recipient, subject, body, category, timestamp)
        cursor = self._db_conn.cursor()
        cursor.execute("INSERT INTO emails VALUES (?,?,?,?,?,?,?)", data)
        self._db_conn.commit()

    def _identify_ticket_from_meta(self, provider, recipients, subject):
        """
            Try to identify an answer to a Cerberus ticket with email meta
        """
        tickets_infos = []
        if not all((provider, recipients, subject)):
            return tickets_infos

        # Trying each recipients
        for recipient in recipients:

            ticket = category = None
            search = self._sender_re.search(str(recipient).lower())
            if search is not None:
                public_id = str(search.group(1)).lower()
                try:
                    ticket = Ticket.get(publicId__iexact=public_id)
                    extract = recipient.split("@")[0].split(".")[1].title()
                    if extract in EMAIL_VALID_CATEGORIES:
                        category = extract
                except (
                    AttributeError,
                    IndexError,
                    TypeError,
                    ValueError,
                    ObjectDoesNotExist,
                ):
                    continue
            if all((ticket, category, recipient)):
                tickets_infos.append((ticket, category, recipient))

        return tickets_infos


def send_email_with_backend(ticket):
    """
        Send an email using SMTP/API or other backend
    """
    if not ticket.mailerId:
        ticket.mailerId = random.randint(1, 100000)
        ticket.save()


def generate_body(ticket, mail_template):

    reports = ticket.reportTicket.all().order_by("-receivedDate")[:10]
    phishing_urls = []
    for rep in reports:
        phishing_urls.extend(rep.get_attached_urls())

    proof = ticket.proof.all().values_list("content", flat=True).distinct()

    template = django_template_engine.from_string(mail_template.body)

    return template.render(
        {
            "publicId": ticket.publicId,
            "phishingUrls": list(set(phishing_urls)),
            "proof": proof,
        }
    )


def generate_subject(ticket, mail_template):

    template = django_template_engine.from_string(mail_template.subject)

    return template.render({"publicId": ticket.publicId})
