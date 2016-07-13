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
    Common functions for worker
"""

from django.core.exceptions import ValidationError
from django.core.validators import validate_email

import database

from factory.factory import ImplementationFactory


def send_email(ticket, emails, template_codename, lang='EN', acknowledged_report_id=None):
    """
        Wrapper to send email
    """
    prefetched_email = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').prefetch_email_from_template(
        ticket,
        template_codename,
        lang=lang,
        acknowledged_report=acknowledged_report_id,
    )

    for email in emails:
        try:
            validate_email(email)
        except ValidationError:
            continue

        ImplementationFactory.instance.get_singleton_of('MailerServiceBase').send_email(
            ticket,
            email,
            prefetched_email.subject,
            prefetched_email.body
        )
        database.log_action_on_ticket(ticket, 'send an email to %s' % (email))
