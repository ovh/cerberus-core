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
    Text utils for Cerberus
"""

import hashlib
import re

from datetime import datetime
from HTMLParser import HTMLParseError

import html2text
from django.db.models import ObjectDoesNotExist
from django.template import TemplateSyntaxError, engines
from django.template.base import TemplateEncodingError


from ..models import MailTemplate
from ..services.email.base import Email


html2text.ignore_images = True
html2text.images_to_alt = True
html2text.ignore_links = True


class EmailThreadTemplateNotFound(Exception):
    """
        EmailThreadTemplateNotFound
    """

    def __init__(self, message):
        super(EmailThreadTemplateNotFound, self).__init__(message)


class EmailThreadTemplateSyntaxError(Exception):
    """
        EmailThreadTemplateSyntaxError
    """

    def __init__(self, message):
        super(EmailThreadTemplateSyntaxError, self).__init__(message)


def dehtmlify(body):
    """
        Try to dehtmlify a text

        :param str body: The html content
        :rtype: str
        :return: The dehtmlified content
    """
    html = html2text.HTML2Text()
    html.body_width = 0

    try:
        body = html.handle(body.replace("\r\n", "<br/>"))
        body = re.sub(r"^(\s*\n){2,}", "\n", body, flags=re.MULTILINE)
    except HTMLParseError:
        pass

    return body


def string_to_underscore_case(string):
    """
        Convert a string to underscore case

        :param str string: The sting to convert
        :rtype: str
        :return: The converted string
    """
    tmp = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", string)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", tmp).lower()


def get_attachment_storage_filename(hash_string=None, content=None, filename=None):
    """
        Generate a pseudo-unique filename based on content and filename

        :param str hash_string: a hash if it has been previously computed
        :param str content: the content of the file
        :param str filename: the real name of the file
    """
    storage_filename = None

    if content:
        hash_string = hashlib.sha256(content).hexdigest()

    storage_filename = hash_string + "-attach-"
    storage_filename = storage_filename.encode("utf-8")
    storage_filename = storage_filename + filename
    return storage_filename


def get_email_thread_content(ticket, emails):
    """
        Generate `abuse.models.Ticket` emails thred history
        based on 'email_thread' `abuse.models.MailTemplate`

        :param `abuse.models.Ticket` ticket: The cererus ticket
        :param list emails: a list of `cerberus.services.email.base.Email`
        :rtype: tuple
        :return: The content and the filetype
    """
    try:
        template = MailTemplate.objects.get(codename="email_thread")
        is_html = "<html>" in template.body
    except ObjectDoesNotExist:
        raise EmailThreadTemplateNotFound("Unable to email_thread")

    _emails = []

    for email in emails:
        _emails.append(
            Email(
                sender=email.sender,
                subject=email.subject,
                recipient=email.recipient,
                body=email.body.replace("\n", "<br>") if is_html else email.body,
                created=datetime.fromtimestamp(email.created),
                category=None,
                attachments=None,
            )
        )

    domain = ticket.service.name if ticket.service else None
    django_template_engine = engines["django"]

    try:
        template = django_template_engine.from_string(template.body)
        content = template.render(
            {
                "publicId": ticket.publicId,
                "creationDate": ticket.creationDate,
                "domain": domain,
                "emails": _emails,
            }
        )
    except (TemplateEncodingError, TemplateSyntaxError) as ex:
        raise EmailThreadTemplateSyntaxError(str(ex))

    try:
        import pdfkit
        from pyvirtualdisplay import Display

        display = Display(visible=0, size=(1366, 768))
        display.start()
        content = pdfkit.from_string(content, False)
        display.stop()
        return content, "application/pdf"
    except:
        return content.encode("utf-8"), "text/html" if is_html else "text/plain"
