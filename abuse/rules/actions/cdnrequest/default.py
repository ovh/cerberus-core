# -*- coding: utf-8 -*-

"""
    Actions for CDNRequest rules
"""

import json

from collections import OrderedDict
from datetime import datetime, timedelta
from time import mktime

from django.forms.models import model_to_dict

from ...engine.actions import rule_action, BaseActions
from ...engine.fields import FIELD_TEXT
from ....models import History, Proof, Ticket, User, ReportItem
from ....utils.cache import redis_lock, RedisHandler
from ....tasks import enqueue_in, helpers


class DefaultCDNRequestActions(BaseActions):
    """
        This class implements actions for CDN requests
    """
    providers = {
        'cloudflare': {
            'email': 'abusereply@cloudflare.com'
        }
    }

    cache_expirations_days = 15
    redis_queue = 'cdnrequest:{}:request'

    def __init__(self, report, domain_to_request):
        """
        """
        self.report = report
        self.domain_to_request = domain_to_request

    @rule_action(params=[{'fieldType': FIELD_TEXT, 'name': 'provider'}])
    def do_cdn_request(self, provider):
        """
            Make request to supported CDN providers
        """
        ticket, expiration = self._retreive_from_cache(provider)

        # if already resolved, just attach report
        if expiration and datetime.now() < expiration:
            self.report.defendant = ticket.defendant
            self.report.service = ticket.service
            self.report.save()
            if all((self.report.defendant, self.report.service)):
                # rexecute report workflow
                self._rexecute_report_workflow(ticket)
        else:  # else, send request to provider
            ticket = self._send_request(provider)

        self.report.ticket = ticket
        self.report.status = 'Attached'
        self.report.save(update_fields=['ticket', 'status'])

        History.log_ticket_action(
            ticket=ticket,
            action='attach_report',
            new_ticket=False,
            report=self.report
        )

    @redis_lock('cdnrequest:lock')
    def _retreive_from_cache(self, provider):
        """
            Check if there is already a pending/resolved similar request
        """
        expiration = ticket = None
        entries = RedisHandler.ldump(
            self.redis_queue.format(provider)
        )

        for entry in entries:
            entry = json.loads(entry, object_pairs_hook=OrderedDict)
            if entry['domain'] == self.domain_to_request:
                ticket = Ticket.get(id=entry['request_ticket_id'])
                expiration = datetime.fromtimestamp(entry['expiration'])
                break

        return ticket, expiration

    @redis_lock('cdnrequest:lock')
    def _send_request(self, provider):
        """
            Send email request to CDN Provider
        """
        ticket = helpers.create_ticket(
            self.report,
            denied_by=None,
            attach_new=False
        )

        ticket.treatedBy = User.objects.get(username='abuse.robot')
        ticket.save()

        self._send_email_request(provider, ticket)
        self._update_cache(ticket, provider)

        return ticket

    def _send_email_request(self, provider, ticket):

        try:
            email = self.providers[provider]['email']
        except KeyError:
            raise Exception("Unsupported CDN provider")

        proof_content = self.report.reportItemRelatedReport.filter(
            itemType='FQDN'
        ).last().rawItem

        Proof.create(
            ticket=ticket,
            content=proof_content
        )

        helpers.send_email(
            ticket,
            [email],
            '{}_ip_request'.format(provider),
            lang='EN'
        )

        ticket.save()

    def _update_cache(self, ticket, provider):

        entries = RedisHandler.ldump(
            self.redis_queue.format(provider)
        )

        # Clear old entries
        for entry in entries:
            entry_json = json.loads(entry)
            if entry_json['domain'] == self.domain_to_request:
                RedisHandler.lrem(self.redis_queue.format(provider), entry)

        # Push task
        RedisHandler.rpush(
            self.redis_queue.format(provider),
            json.dumps({
                'domain': self.domain_to_request,
                'request_ticket_id': ticket.id,
                'expiration': self._get_expiration()
            }),
        )

    def _get_expiration(self):

        exp = datetime.now() + timedelta(days=self.cache_expirations_days)
        return int(mktime(exp.timetuple()))

    def _rexecute_report_workflow(self, ticket):

        # attach resolved URLs
        self.report.attach_url_matching_domain(self.domain_to_request)

        # attach resolved IP address
        item = ticket.reportTicket.first().reportItemRelatedReport.filter(
            itemType='IP'
        ).last()
        item = model_to_dict(item)
        item.pop('id')
        item['report'] = self.report
        ReportItem.create(**item)

        # schedule job
        enqueue_in(
            timedelta(seconds=10),
            'report.validate_with_defendant',
            report_id=self.report.id,
            timeout=3600
        )
