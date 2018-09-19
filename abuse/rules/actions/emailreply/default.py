# -*- coding: utf-8 -*-

"""
    Actions for EmailReply rules
"""

from datetime import timedelta

from ...engine.actions import rule_action, BaseActions
from ...engine.fields import FIELD_TEXT, FIELD_NO_INPUT, FIELD_NUMERIC
from ...variables import CDNRequestVariables
from ....models import Defendant, Service, ReportItem, History
from ....tasks import enqueue, enqueue_in, helpers
from ....services import CRMService, EmailService
from ....utils import networking


class DefaultEmailReplyActions(BaseActions):
    """
        This class implements usefull actions required
        for EmailReply `abuse.models.BusinessRules`
    """

    def __init__(self, ticket, abuse_report, recipient, category):
        """
            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `cerberus.parsers.ParsedEmail` self.parsed_email: the email
            :param str recipient: The recipient of the answer
            :param str category: defendant, plaintiff or other
        """
        self.ticket = ticket
        self.parsed_email = abuse_report
        self.email_recipient = recipient
        self.email_category = category

    @rule_action(params=[{"fieldType": FIELD_TEXT, "name": "provider"}])
    def cdn_response_update(self, provider):
        """
        """
        services = CRMService.get_services_from_items(ips=self.parsed_email.ips)

        # something went wrong
        if len(services) != 1:
            self.ticket.set_status("Alarm")
            self.ticket.treatedBy = None
            self.ticket.save(update_fields=["treatedBy"])
            return

        update_cdn_ticket(services, self.ticket, self.parsed_email.ips, provider)

    @rule_action()
    def attach_external_answer(self):
        """
        """
        History.log_ticket_action(
            ticket=self.ticket, action="receive_email", email=self.parsed_email.provider
        )

        EmailService.attach_external_answer(
            self.ticket,
            self.parsed_email.provider,
            self.email_recipient,
            self.parsed_email.subject,
            self.parsed_email.body,
            self.email_category,
            attachments=self.parsed_email.attachments,
        )

    @rule_action()
    def cancel_pending_jobs(self):
        """
        """
        enqueue(
            "ticket.cancel_pending_jobs", ticket_id=self.ticket.id, status="answered"
        )

    @rule_action()
    def try_resend(self):

        emails = EmailService.get_emails(self.ticket)
        emails = [eml for eml in emails if eml.category.lower() == "defendant"]
        tried_emails = [email.recipient for email in emails]

        email_to_resend = None
        for email in reversed(emails):
            if email.body.strip() in self.parsed_email.body.strip():
                email_to_resend = email
                break

        # Set to Alarm
        if any(
            (
                not email_to_resend,
                not self.ticket.defendant.details.spareEmail,
                self.ticket.defendant.details.spareEmail in tried_emails,
                self.ticket.defendant.details.spareEmail
                == self.ticket.defendant.details.email,
            )
        ):
            self.ticket.set_status("Alarm")
        else:  # or retry
            EmailService.send_email(
                self.ticket,
                self.ticket.defendant.details.spareEmail,
                email_to_resend.subject,
                email_to_resend.body,
                email_to_resend.category,
            )
            History.log_ticket_action(
                ticket=self.ticket, action="send_email", email=email
            )

    @rule_action(
        params=[
            {"fieldType": FIELD_TEXT, "name": "resolution"},
            {"fieldType": FIELD_NO_INPUT, "name": "keep_update"},
        ]
    )
    def close_ticket(self, resolution=None, keep_update=False):
        """
        """
        helpers.close_ticket(self.ticket, resolution_codename=resolution)
        self.ticket.update = keep_update
        self.ticket.save()

    @rule_action(
        params=[
            {"fieldType": FIELD_TEXT, "name": "template_codename"},
            {"fieldType": FIELD_TEXT, "name": "email"},
            {"fieldType": FIELD_TEXT, "name": "lang"},
        ]
    )
    def send_email(self, template_codename=None, email=None, lang=None):
        """
        """
        if not all((template_codename, email)):
            raise ValueError("invalid params")

        if not lang:
            lang = self.ticket.defendant.details.lang

        helpers.send_email(self.ticket, [email], template_codename, lang=lang)

    @rule_action(
        params=[
            {"fieldType": FIELD_TEXT, "name": "task_name"},
            {"fieldType": FIELD_NUMERIC, "name": "seconds"},
            {"fieldType": FIELD_NO_INPUT, "name": "task_params"},
        ]
    )
    def enqueue_ticket_task(self, task_name=None, seconds=60, task_params=None):
        """
            Schedule a ticket task

            :param str task_name: name of task to enqueue
            :param int seconds: task will pop up in "seconds" seconds
            :param dict task_name: dict of task paramsof task to enqueue
        """
        if not task_name:
            raise ValueError('missing "task_name" param')

        if not task_params:
            task_params = {}

        enqueue_in(
            timedelta(seconds=seconds),
            task_name,
            ticket_id=self.ticket.id,
            **task_params
        )

    @rule_action(params=[{"fieldType": FIELD_TEXT, "name": "status"}])
    def set_ticket_status(self, status):
        """
        """
        if status != self.ticket.status:
            self.ticket.set_status(status)


def update_cdn_ticket(services, ticket, ips, provider):
    """
        Update ticket with defendant/service infos
    """
    defendant = Defendant.get_or_create_defendant(services[0]["defendant"])
    service = Service.get_or_create_service(services[0]["service"])

    ticket.status = ticket.previousStatus
    ticket.status = "Open"
    ticket.defendant = defendant
    ticket.service = service
    ticket.treatedBy = None
    ticket.save()

    ticket.reportTicket.all().update(defendant=defendant, service=service)

    _create_items(ticket, ips[0], provider)

    # rexecute report workflow
    enqueue_in(
        timedelta(seconds=10),
        "report.validate_with_defendant",
        report_id=ticket.reportTicket.last().id,
        timeout=3600,
    )


def _create_items(ticket, ip_addr, provider):

    # Resolved IP
    item_dict = {
        "itemType": "IP",
        "report_id": ticket.reportTicket.first().id,
        "rawItem": ip_addr,
    }

    item_dict.update(networking.get_reverses_for_item(ip_addr, nature="IP"))
    ReportItem.create(**item_dict)

    domain = CDNRequestVariables.get_requested_domain(ticket.id, provider)

    # Corresponding URLs
    for report in ticket.reportTicket.all():
        report.attach_url_matching_domain(domain)
