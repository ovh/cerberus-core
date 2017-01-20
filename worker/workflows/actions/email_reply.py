# -*- coding: utf-8 -*-

"""
    Actions for EmailReply rules
"""

import json
from collections import OrderedDict

from factory import implementations
from utils import utils
from worker.common import CDN_REQUEST_LOCK, CDN_REQUEST_REDIS_QUEUE
from worker.workflows.engine.actions import rule_action, BaseActions
from worker.workflows.engine.fields import FIELD_TEXT
from worker import database


class EmailReplyActions(BaseActions):
    """
        This class implements usefull actions required for EmailReply `abuse.models.BusinessRules`
    """
    def __init__(self, ticket, abuse_report, recipient, category):
        """
            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `worker.parsing.parsed.ParsedEmail` self.parsed_email: the email
            :param str recipient: The recipient of the answer
            :param str category: defendant, plaintiff or other
        """
        self.ticket = ticket
        self.parsed_email = abuse_report
        self.email_recipient = recipient
        self.email_category = category

    @rule_action(params=[{'fieldType': FIELD_TEXT, 'name': 'provider'}])
    def cdn_response_update(self, provider):
        """
        """
        services = implementations.get_singleton_of(
            'CustomerDaoBase'
        ).get_services_from_items(
            ips=self.parsed_email.ips,
        )

        if len(services) != 1:
            alarm_ticket(self.ticket)
        else:
            update_ticket(services, self.ticket, provider)

    @rule_action()
    def attach_external_answer(self):
        """
        """
        database.log_action_on_ticket(
            ticket=self.ticket,
            action='receive_email',
            email=self.parsed_email.provider
        )

        implementations.get_singleton_of('MailerServiceBase').attach_external_answer(
            self.ticket,
            self.parsed_email.provider,
            self.email_recipient,
            self.parsed_email.subject,
            self.parsed_email.body,
            self.email_category,
            attachments=self.parsed_email.attachments
        )

    @rule_action()
    def cancel_pending_jobs(self):
        """
        """
        utils.default_queue.enqueue(
            'ticket.cancel_rq_scheduler_jobs',
            ticket_id=self.ticket.id,
            status='answered'
        )

    @rule_action(params=[{'fieldType': FIELD_TEXT, 'name': 'status'}])
    def set_ticket_status(self, status):
        """
        """
        self.ticket.previousStatus = self.ticket.status
        self.ticket.status = status.title()
        self.ticket.snoozeStart = None
        self.ticket.snoozeDuration = None
        self.ticket.save()

        database.log_action_on_ticket(
            ticket=self.ticket,
            action='change_status',
            previous_value=self.ticket.previousStatus,
            new_value=self.ticket.status,
        )

    @rule_action()
    def try_resend(self):

        emails = implementations.get_singleton_of(
            'MailerServiceBase'
        ).get_emails(self.ticket)
        emails = [email for email in emails if email.category.lower() == 'defendant']
        tried_emails = [email.recipient for email in emails]

        email_to_resend = None
        for email in reversed(emails):
            if email.body.strip() in self.parsed_email.body.strip():
                email_to_resend = email
                break

        # Set to Alarm
        if any((not email_to_resend,
                not self.ticket.defendant.details.spareEmail,
                self.ticket.defendant.details.spareEmail in tried_emails,
                self.ticket.defendant.details.spareEmail == self.ticket.defendant.details.email)):
            self.set_ticket_status('Alarm')
        else:  # or retry
            implementations.get_singleton_of('MailerServiceBase').send_email(
                self.ticket,
                self.ticket.defendant.details.spareEmail,
                email_to_resend.subject,
                email_to_resend.body,
                email_to_resend.category
            )
            database.log_action_on_ticket(
                ticket=self.ticket,
                action='send_email',
                email=email
            )


@utils.redis_lock(CDN_REQUEST_LOCK)
def update_redis_cache(ticket_id, defendant_id, service_id, provider):
    """
        Update pending request in cache with now resolved infos
    """
    queue = CDN_REQUEST_REDIS_QUEUE % provider
    for entry in utils.redis.lrange(queue, 0, -1):
        entry = json.loads(entry, object_pairs_hook=OrderedDict)
        if entry['request_ticket_id'] == ticket_id:
            utils.redis.rpush(
                queue,
                json.dumps({
                    'domain': entry['domain'],
                    'defendant_id': defendant_id,
                    'service_id': service_id,
                    'request_ticket_id': ticket_id,
                    'expiration': entry['expiration']
                }),
            )
            utils.redis.lrem(
                queue,
                json.dumps(entry)
            )
            return


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


def update_ticket(services, ticket, provider):
    """
        Update ticket with defendant/service infos
    """
    defendant = database.get_or_create_defendant(services[0]['defendant'])
    service = database.get_or_create_service(services[0]['service'])
    update_redis_cache(ticket.id, defendant.id, service.id, provider)

    ticket.status = ticket.previousStatus
    ticket.status = 'Open'
    ticket.defendant = defendant
    ticket.service = service
    ticket.treatedBy = None
    ticket.save()

    ticket.reportTicket.all().update(
        defendant=defendant,
        service=service
    )
