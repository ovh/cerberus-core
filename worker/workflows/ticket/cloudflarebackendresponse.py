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
    Handle Cloudflare backend request workflow

    see worker/workflows/cdnrequest/cloudflare.py
"""

import json
from collections import OrderedDict

from django.conf import settings

from abuse.models import User
from factory.implementation import ImplementationFactory
from utils import utils
from worker import Logger, database
from worker.workflows.cdnrequest import cloudflare
from worker.workflows.ticket.abstract import TicketAnswerWorkflowBase


BOT_USER = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])


class CloudflareBackendResponse(TicketAnswerWorkflowBase):
    """
        Handle Cloudflare backend request workflow
    """
    def identify(self, ticket, abuse_report, recipient, category):
        """
            identify if the `abuse.models.Report` match this workflow.

            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `worker.parsing.parsed.ParsedEmail` abuse_report: the email
            :param str recipient: The recipient of the answer
            :param str category: defendant, plaintiff or other
            :return: If the workflow match
            :rtype: bool
        """
        if (abuse_report.provider == cloudflare.CLOUDFLARE_EMAIL and
                ticket.treatedBy.username == BOT_USER.username and
                check_if_ticket_in_cache(ticket.id)):
            return True
        return False

    def apply(self, ticket, abuse_report, recipient, category):
        """
            Apply specific answer workflow on given `abuse.models.Ticket`

            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `worker.parsing.parsed.ParsedEmail` abuse_report: the email
            :param str recipient: The recipient of the answer
            :param str category: defendant, plaintiff or other
            :return: If the workflow is applied
            :rtype: bool
        """
        services = ImplementationFactory.instance.get_singleton_of(
            'CustomerDaoBase'
        ).get_services_from_items(
            urls=abuse_report.urls,
            ips=abuse_report.ips,
            fqdn=abuse_report.fqdn
        )

        if len(services) != 1:
            Logger.error(unicode('Cloudflare request does not contains valid IP'))
            alarm_ticket(ticket)
            return True

        defendant = database.get_or_create_defendant(services[0]['defendant'])
        service = database.get_or_create_service(services[0]['service'])
        update_redis_cache(ticket.id, defendant.id, service.id)

        ticket.status = ticket.previousStatus
        ticket.status = 'Open'
        ticket.defendant = defendant
        ticket.service = service
        ticket.save()

        ticket.reportTicket.all().update(
            defendant=defendant,
            service=service
        )
        return True


@utils.redis_lock(cloudflare.LOCK_REDIS_QUEUE)
def check_if_ticket_in_cache(ticket_id):
    """
        Check if the answered ticket is in the request cache
    """
    for entry in utils.redis.lrange(cloudflare.REQUEST_REDIS_QUEUE, 0, -1):
        entry = json.loads(entry)
        if int(entry['request_ticket_id']) == int(ticket_id):
            return True

    return False


def alarm_ticket(ticket):
    """
        Set alarm to ticket
    """
    ticket.status = ticket.previousStatus
    ticket.status = 'Alarm'
    ticket.save()

    database.log_action_on_ticket(
        ticket=ticket,
        action='change_status',
        previous_value=ticket.previousStatus,
        new_value=ticket.status
    )


@utils.redis_lock(cloudflare.LOCK_REDIS_QUEUE)
def update_redis_cache(ticket_id, defendant_id, service_id):
    """
        Update pending request in cache with now resolved infos
    """
    for entry in utils.redis.lrange(cloudflare.REQUEST_REDIS_QUEUE, 0, -1):
        entry = json.loads(entry, object_pairs_hook=OrderedDict)
        if entry['request_ticket_id'] == ticket_id:
            utils.redis.rpush(
                cloudflare.REQUEST_REDIS_QUEUE,
                json.dumps({
                    'domain': entry['domain'],
                    'defendant_id': defendant_id,
                    'service_id': service_id,
                    'request_ticket_id': ticket_id,
                    'expiration': entry['expiration']
                }),
            )
            utils.redis.lrem(
                cloudflare.REQUEST_REDIS_QUEUE,
                json.dumps(entry)
            )
            return
