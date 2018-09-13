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
    Defines Mailer Service abstract class
"""

import abc
import inspect

from collections import namedtuple

from ...models import MailTemplate

Email = namedtuple(
    'Email',
    [
        'sender',       # str
        'recipient',    # str
        'created',      # str
        'subject',      # str
        'body',         # str
        'category',     # Category : 'Defendant', 'Plaintiff' or 'Other'
        'attachments'   # List of Attachments
    ]
)

PrefetchedEmail = namedtuple(
    'PrefetchedEmail',
    [
        'sender',       # str
        'recipients',   # list
        'subject',      # str
        'body',         # str
        'category',     # 'Defendant', 'Plaintiff' or 'Other'
    ]
)

EMAIL_VALID_CATEGORIES = [t[0].title() for t in MailTemplate.RECIPIENT_TYPE]


class EmailServiceException(Exception):
    """
        Exception that must be raised by EmailService implementations
        to ensure error are correctly handled.

        .. py:class:: EmailServiceException
    """
    def __init__(self, message):
        super(EmailServiceException, self).__init__(message)


class EmailServiceBase(object):
    """
        Abstract class defining mailer services required by Cerberus

        raise ..py:exception:: EmailServiceException

    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def send_email(self, ticket, recipient, subject, body,
                   category, sender=None, attachments=None):
        """
            Send a email.

            :param `abuse.models.Ticket` ticket: A ticket instance
            :param str recipient: The recipient of the email
            :param str subject: The subject of the email
            :param str body: The body of the email
            :param str category: `cerberus.services.email.base.EMAIL_VALID_CATEGORIES`
            :param str sender: Eventually the sender of the email (From)
            :param list attachments: `cerberus.parsers.ParseEmail` attachments
            :raises `cerberus.services.email.base.EmailServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def get_emails(self, ticket):
        """
            Get all emails for the given ticket

            :param `abuse.models.Ticket` ticket: A ticket instance
            :return: A list of `cerberus.services.email.base.Email` object
            :rtype: list
            :raises `cerberus.services.email.base.EmailServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
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
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def attach_external_answer(self, ticket, sender, recipient,
                               subject, body, category, attachments=None):
        """
            Usefull if an answer for a ticket come from
            Phone/CRM/API/CustomerUX/Other mailbox ...

            :param `abuse.models.Ticket` ticket: A ticket instance
            :param str sender: The sender of the email
            :param str recipient: The recipient of the answer
            :param str subject: The subject of the email
            :param str body: The body of the email
            :param str category: `cerberus.services.email.base.EMAIL_VALID_CATEGORIES`
            :param list attachments: `cerberus.parsers.ParsedEmail` attachments
            :raises `cerberus.services.email.base.EmailServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def prefetch_email_from_template(self, ticket, template_codename,
                                     lang='EN', acknowledged_report=None):
        """
            Try to fill email template with ticket meta

            :param `abuse.models.Ticket` ticket: A ticket instance
            :param str template: The codename of the template
            :param str lang: The langage to use
            :param int acknowledged_report: The id of the source report
            :return: The prefetched email
            :rtype: `cerberus.services.email.base.PrefetchedEmail`
            :raises `cerberus.services.email.base.EmailServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def close_thread(self, ticket):
        """
            Usefull for archive/index/notify/send summary to customer

            :param `abuse.models.Ticket` ticket: A ticket instance
            :raises `cerberus.services.email.base.EmailServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )
