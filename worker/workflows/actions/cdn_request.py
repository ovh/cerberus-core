# -*- coding: utf-8 -*-

"""
    Actions for CDNRequest rules
"""

import json

from collections import OrderedDict
from datetime import datetime, timedelta
from time import mktime

from abuse.models import Defendant, Proof, Service, Ticket
from utils import utils
from worker import common
from worker.workflows.engine.actions import rule_action, BaseActions
from worker.workflows.engine.fields import FIELD_TEXT

CLOUDFLARE_EMAIL = 'abusereply@cloudflare.com'


class CDNRequestActions(BaseActions):
    """
        This class implements usefull actions required for EmailReply `abuse.models.BusinessRules`
    """
    def __init__(self, report, domain_to_request):
        """
            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `worker.parsing.parsed.ParsedEmail` self.parsed_email: the email
            :param str recipient: The recipient of the answer
            :param str category: defendant, plaintiff or other
        """
        self.report = report
        self.domain_to_request = domain_to_request

    @rule_action(params=[{'fieldType': FIELD_TEXT, 'name': 'provider'}])
    def do_cloudflare_request(self, provider):
        """
        """
        defendant, service, ticket, expiration = get_task_from_cache(
            self.domain_to_request,
            provider
        )

        if expiration and datetime.now() < expiration:
            if all((defendant, service)):  # Already resolved
                self.report.defendant = defendant
                self.report.service = service
            self.report.ticket = ticket
            self.report.status = 'Attached'
        else:
            create_request_ticket(self.report, self.domain_to_request, provider)

        self.report.save()
        return True


@utils.redis_lock(common.CDN_REQUEST_LOCK)
def get_task_from_cache(domain_to_request, provider):
    """
        Check if there is already a pending/resolved similar request
    """
    defendant = service = expiration = ticket = None

    for entry in utils.redis.lrange(common.CDN_REQUEST_REDIS_QUEUE % provider, 0, -1):
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


@utils.redis_lock(common.CDN_REQUEST_LOCK)
def create_request_ticket(report, domain_to_request, provider):
    """
        Send email request to CloudFlare
    """
    ticket = common.create_ticket(
        report,
        denied_by=None,
        attach_new=False
    )

    ticket.treatedBy = common.BOT_USER
    ticket.save()

    if provider.lower() == 'cloudflare':
        _send_cloudflare_email_request(ticket, report)
    else:
        raise Exception("Unsupported CDN provider")

    report.ticket = ticket
    report.status = 'Attached'

    utils.redis.rpush(
        common.CDN_REQUEST_REDIS_QUEUE % provider,
        json.dumps({
            'domain': domain_to_request,
            'defendant_id': None,
            'service_id': None,
            'request_ticket_id': ticket.id,
            'expiration': int(mktime((datetime.now() + timedelta(days=15)).timetuple()))
        }),
    )


def _send_cloudflare_email_request(ticket, report):

    proof_content = report.reportItemRelatedReport.filter(
        itemType='FQDN'
    ).last().rawItem

    Proof.objects.create(
        ticket=ticket,
        content=proof_content
    )

    common.send_email(
        ticket,
        [CLOUDFLARE_EMAIL],
        'cloudflare_ip_request',
        lang='EN'
    )

    ticket.save()
