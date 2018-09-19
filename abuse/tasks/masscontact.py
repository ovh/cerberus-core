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
    MassContact functions for worker
"""

import hashlib
import logging

from collections import Counter
from datetime import datetime
from time import sleep

from django.core.validators import validate_ipv46_address
from django.db import transaction
from django.template import Context, engines


from . import helpers, Queues
from ..models import (
    Category,
    Defendant,
    MassContactResult,
    Report,
    History,
    Service,
    Provider,
    ReportItem,
    User,
)
from ..services import CRMService, EmailService
from ..utils import networking, pglocks

django_template_engine = engines["django"]


def mass_contact(
    ip_address=None,
    category=None,
    campaign_name=None,
    email_subject=None,
    email_body=None,
    user_id=None,
):
    """
        Try to identify customer based on `ip_address`, creates Cerberus ticket
        then send email to customer and finally close ticket.

        The use case is: a trusted provider sent you
        a list of vulnerable DNS servers (DrDOS amp) for example.

        To prevent abuse on your network, you notify customer
        of this vulnerability.

        :param str ip_address: The IP address
        :param str category: The category of the abuse
        :param str campaign_name: The name if the "mass-conctact" campaign
        :param str email_subject: The subject of the email to send to defendant
        :param str email_body: The body of the email to send to defendant
        :param int user_id: Id of `abuse.models.User` campaign creator
    """
    validate_ipv46_address(ip_address)

    category = Category.get(name=category)
    user = User.objects.get(id=user_id)

    # Identify service for ip_address
    services = CRMService.get_services_from_items(ips=[ip_address])

    # Create report/ticket
    if services:
        logging.debug(
            unicode("creating report/ticket for ip address %s" % (ip_address))
        )
        with pglocks.advisory_lock("cerberus_lock"):
            _create_contact_tickets(
                services,
                campaign_name,
                ip_address,
                category,
                email_subject,
                email_body,
                user,
            )
        return True
    logging.debug(unicode("no service found for ip address %s" % (ip_address)))
    return False


@transaction.atomic
def _create_contact_tickets(
    services, campaign_name, ip_address, category, email_subject, email_body, user
):

    # Create fake report
    report_subject = "Campaign %s for ip %s" % (campaign_name, ip_address)
    report_body = "Campaign: %s\nIP Address: %s\n" % (campaign_name, ip_address)
    filename = hashlib.sha256(report_body.encode("utf-8")).hexdigest()
    helpers.save_email(filename, report_body)

    for data in services:  # For identified (service, defendant, items) tuple

        # Create report
        report = Report.create(
            **{
                "provider": Provider.get_or_create_provider("mass_contact"),
                "receivedDate": datetime.now(),
                "subject": report_subject,
                "body": report_body,
                "category": category,
                "filename": filename,
                "status": "Archived",
                "defendant": Defendant.get_or_create_defendant(data["defendant"]),
                "service": Service.get_or_create_service(data["service"]),
            }
        )
        History.log_new_report(report)

        # Create item
        item_dict = {"itemType": "IP", "report_id": report.id, "rawItem": ip_address}
        item_dict.update(networking.get_reverses_for_item(ip_address, nature="IP"))
        ReportItem.create(**item_dict)

        # Create ticket
        ticket = helpers.create_ticket(report, attach_new=False)
        ticket.add_tag(campaign_name)

        # Send email to defendant
        _send_mass_contact_email(ticket, email_subject, email_body)

        # Close ticket/report
        helpers.close_ticket(ticket, "fixed_by_customer")


def _send_mass_contact_email(ticket, email_subject, email_body):

    template = django_template_engine.from_string(email_subject)
    context = Context(
        {
            "publicId": ticket.publicId,
            "service": ticket.service.name.replace(".", "[.]"),
            "lang": ticket.defendant.details.lang,
        }
    )
    subject = template.render(context)

    template = django_template_engine.from_string(email_body)
    context = Context(
        {
            "publicId": ticket.publicId,
            "service": ticket.service.name.replace(".", "[.]"),
            "lang": ticket.defendant.details.lang,
        }
    )
    body = template.render(context)

    EmailService.send_email(
        ticket, ticket.defendant.details.email, subject, body, "MassContact"
    )


def check_mass_contact_result(result_campaign_id=None, jobs=None):
    """
        Check "mass-contact" campaign jobs's result

        :param int result_campaign_id: `abuse.models.MassContactResult` id
        :param list jobs: The list of associated Python-Rq jobs id
    """
    campaign_result = MassContactResult.get(id=result_campaign_id)

    result = []
    for job_id in jobs:
        job = Queues.default.fetch_job(job_id)
        if not job:
            continue
        while job.status.lower() == "queued":
            sleep(0.5)
        result.append(job.result)

    count = Counter(result)
    campaign_result.state = "Done"
    campaign_result.matchingCount = count[True]
    campaign_result.notMatchingCount = count[False]
    campaign_result.failedCount = count[None]
    campaign_result.save()
    logging.info(
        unicode("MassContact campaign {} finished".format(campaign_result.campaign.id))
    )
