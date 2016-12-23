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
    Defined Cloudflare implementation of CDNRequestWorkflowBase
"""

import json

from datetime import datetime, timedelta
from collections import OrderedDict
from time import mktime

from django.conf import settings

from abuse.models import Defendant, Service, Ticket, User, Proof
from utils import utils
from worker import database, common
from worker.workflows.cdnrequest.abstract import CDNRequestWorkflowBase

BOT_USER = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

CACHE_EXPIRATION_DAYS = 15
REQUEST_REDIS_QUEUE = 'cdnrequest:cloudflare:request'
LOCK_REDIS_QUEUE = 'cdnrequest:cloudflare:lock'
CLOUDFLARE_EMAIL = 'abusereply@cloudflare.com'


class CloudflareRequest(CDNRequestWorkflowBase):
    """
        This class interact with Cloudflare to request real backend IP for a domain name
    """
    def identify(self, report, domain_to_request):
        """
            identify if the `abuse.models.Report` and the domain_to_request match the CDN provider

            :param `abuse.models.Report` report: A Cerberus report instance
            :param str domain_to_request: the domain name to request
            :return: If the workflow match
            :rtype: bool
        """
        if not domain_to_request:
            return False

        ips = utils.get_ips_from_fqdn(domain_to_request)
        if not ips:
            return False

        for ip_addr in ips:
            if utils.get_ip_network(ip_addr) == 'cloudflare':
                return True

        return False

    def apply(self, report, domain_to_request):
        """
            Request backend IP for given domain to CDN`

            :param `abuse.models.Report` report: A Cerberus report instance
            :param str domain_to_request: the domain name to request
            :return: If the workflow is applied
            :rtype: bool
        """
        defendant, service, ticket, expiration = get_task_from_cache(domain_to_request)

        if expiration and datetime.now() < expiration:
            if all((defendant, service)):  # Already resolved
                report.defendant = defendant
                report.service = service
                attach_report_to_ticket(report)
            elif ticket:  # Pending request
                report.ticket = ticket
                report.status = 'Attached'
        else:
            create_request_ticket(report, domain_to_request)

        report.save()
        return True


@utils.redis_lock(LOCK_REDIS_QUEUE)
def get_task_from_cache(domain_to_request):
    """
        Check if there is already a pending/resolved similar request
    """
    defendant = service = expiration = ticket = None

    for entry in utils.redis.lrange(REQUEST_REDIS_QUEUE, 0, -1):
        entry = json.loads(entry, object_pairs_hook=OrderedDict)
        if entry['domain'] == domain_to_request:
            defendant = Defendant.objects.filter(
                id=entry['defendant_id']
            ).last()
            service = Service.objects.filter(
                id=entry['service_id']
            ).last()
            ticket = Ticket.objects.get(
                id=entry['request_ticket_id']
            )
            expiration = datetime.fromtimestamp(entry['expiration'])
            break

    return defendant, service, ticket, expiration


def attach_report_to_ticket(report):

    ticket = database.search_ticket(
        report.defendant,
        report.category,
        report.service
    )

    if not ticket:
        ticket = common.create_ticket(
            report,
            denied_by=None,
            attach_new=True
        )

    report.ticket = ticket
    report.status = 'Attached'


@utils.redis_lock(LOCK_REDIS_QUEUE)
def create_request_ticket(report, domain_to_request):
    """
        Send email request to CloudFlare
    """
    ticket = common.create_ticket(
        report,
        denied_by=None,
        attach_new=False
    )

    proof_content = report.reportItemRelatedReport.filter(
        itemType='FQDN'
    ).last().rawItem

    Proof.objects.create(
        ticket=ticket,
        content=proof_content
    )

    ticket.treatedBy = BOT_USER
    ticket.save()

    report.ticket = ticket
    report.status = 'Attached'

    common.send_email(
        ticket,
        [CLOUDFLARE_EMAIL],
        'cloudflare_ip_request',
        lang='EN'
    )

    utils.redis.rpush(
        REQUEST_REDIS_QUEUE,
        json.dumps({
            'domain': domain_to_request,
            'defendant_id': None,
            'service_id': None,
            'request_ticket_id': ticket.id,
            'expiration': int(mktime((datetime.now() + timedelta(days=15)).timetuple()))
        }),
    )
