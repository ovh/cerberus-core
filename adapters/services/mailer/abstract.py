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
    Defined Mailer Service abstract class
"""

import abc
from collections import namedtuple

from abuse.models import MailTemplate

Email = namedtuple('Email', ['sender', 'recipient', 'created', 'subject', 'body', 'category'])  # Category : 'defendant', 'plaintiff' or 'other'
PrefetchedEmail = namedtuple('PrefetchedEmail', ['sender', 'recipients', 'subject', 'body', 'category'])  # 'recipients' is a list

EMAIL_VALID_CATEGORIES = [t[0] for t in MailTemplate.RECIPIENT_TYPE]


class MailerServiceException(Exception):
    """
        Exception that must be raised by MailerService implementations to ensure error are correctly handled.

        .. py:class:: MailerServiceException
    """
    def __init__(self, message):
        super(MailerServiceException, self).__init__(message)


class MailerServiceBase(object):
    """
        Abstract class defining mailer services required by Cerberus

        The only exception allowed to be raised is ..py:exception:: MailerServiceException

    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def send_email(self, ticket, recipient, subject, body, category, sender=None):
        """
            Send a email.

            :param Ticket ticket: A Cerberus ticket instance.
            :param str recipient: The recipient of the email
            :param str subject: The subject of the email
            :param str body: The body of the email
            :param str sender: Eventually the sender of the email (From)
            :param str category: defendant, plaintiff or other
            :raises MailerServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'send_email'" % (cls))

    @abc.abstractmethod
    def get_emails(self, ticket):
        """
            Get all emails for the given ticket

            :param Ticket ticket: A Cerberus ticket instance.
            :return: A list of Email object
            :rtype: list
            :raises MailerServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'get_emails'" % (cls))

    @abc.abstractmethod
    def is_email_ticket_answer(self, email):
        """
            Returns if the email is an answer to a `abuse.models.Ticket`

            :param `worker.parsing.parser.ParsedEmail` email: The parsed email
            :return: the tuple (`abuse.models.Ticket`, category) or (None, None)  # Category : 'defendant', 'plaintiff' or 'other'
            :rtype: tuple
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'is_email_answer'" % (cls))

    @abc.abstractmethod
    def attach_external_answer(self, ticket, sender, subject, body, category):
        """
            Usefull if an answer for a ticket come from Phone/CRM/API/CustomerUX/Other mailbox ...

            :param Ticket ticket: A Cerberus ticket instance.
            :param str sender: The sender of the email
            :param str subject: The subject of the email
            :param str body: The body of the email
            :param str category: defendant, plaintiff or other
            :raises MailerServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'attach_external_answer'" % (cls))

    @abc.abstractmethod
    def prefetch_email_from_template(self, ticket, template_codename, lang='EN', acknowledged_report=None):
        """
            Try to fill email template with ticket meta

            :param Ticket ticket: A Cerberus ticket instance.
            :param str template: The codename of the template
            :param str lang: The langage to use
            :param int acknowledged_report: Eventually add a report body to the email body (e.g for acknowledgment)
            :return: The prefetched email
            :rtype: PrefetchedEmail
            :raises MailerServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'prefetch_email_from_template'" % (cls))

    @abc.abstractmethod
    def close_thread(self, ticket):
        """
            Usefull for archive/index/notify/send summary to customer

            :param Ticket ticket: A Cerberus ticket instance.
            :raises MailerServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'close_thread'" % (cls))
