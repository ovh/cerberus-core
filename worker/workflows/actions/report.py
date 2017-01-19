# -*- coding: utf-8 -*-

"""
    Business rules for new abuse report
"""

import re
from datetime import datetime, timedelta

from abuse.models import Proof, Resolution
from config import settings
from factory.implementation import ImplementationFactory
from utils import utils
from worker.parsing import regexp
from worker.workflows.engine.actions import rule_action, BaseActions
from worker.workflows.engine.fields import (FIELD_TEXT,
                                            FIELD_NO_INPUT,
                                            FIELD_NUMERIC)
from worker import common, database, phishing


class ReportActions(BaseActions):
    """
        This class implements usefull actions required for rules
    """
    def __init__(self, report, ticket):
        """
            :param `abuse.models.Report` report: A Cerberus report instance
            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
        """
        self.report = report
        self.ticket = ticket
        self.existing_ticket = bool(ticket)

    @rule_action(params=[{'fieldType': FIELD_NO_INPUT, 'name': 'create_new'},
                         {'fieldType': FIELD_NO_INPUT, 'name': 'attach_new'}])
    def create_ticket(self, create_new=False, attach_new=True):
        """
        """
        if create_new or not self.ticket:
            self.ticket = database.create_ticket(
                self.report.defendant,
                self.report.category,
                self.report.service,
                attach_new=attach_new
            )

        self.report.ticket = self.ticket
        self.report.status = 'Attached'
        self.report.save()

        database.log_action_on_ticket(
            ticket=self.ticket,
            action='attach_report',
            report=self.report,
            new_ticket=not self.existing_ticket
        )
        database.set_ticket_higher_priority(self.ticket)

    @rule_action(params=[{'fieldType': FIELD_TEXT, 'name': 'resolution'},
                         {'fieldType': FIELD_NO_INPUT, 'name': 'keep_update'}])
    def close_ticket(self, resolution=None, keep_update=False):
        """
        """
        resolution_obj = close_reason = None
        if resolution:
            resolution_obj = Resolution.objects.get(codename=settings.CODENAMES[resolution])
            close_reason = resolution_obj.codename

        ImplementationFactory.instance.get_singleton_of(
            'MailerServiceBase'
        ).close_thread(self.ticket)

        self.ticket.resolution = resolution_obj
        self.ticket.previousStatus = self.ticket.status
        self.ticket.status = 'Closed'
        self.ticket.update = keep_update
        self.ticket.save()
        database.log_action_on_ticket(
            ticket=self.ticket,
            action='change_status',
            previous_value=self.ticket.previousStatus,
            new_value=self.ticket.status,
            close_reason=close_reason
        )
        self.report.status = 'Archived'
        self.report.save()

    @rule_action()
    def send_provider_ack(self):
        """
        """
        common.send_email(
            self.ticket,
            [self.report.provider.email],
            settings.CODENAMES['ack_received'],
            lang='EN',
            acknowledged_report_id=self.report.id,
        )

    @rule_action()
    def send_defendant_first_alert(self):
        """
        """
        common.send_email(
            self.ticket,
            [self.report.defendant.details.email],
            settings.CODENAMES['first_alert'],
            lang=self.report.defendant.details.lang,
            acknowledged_report_id=self.report.id
        )

    @rule_action()
    def add_ticket_acns_proof(self):
        """
        """
        content = regexp.ACNS_PROOF.search(self.report.body).group()

        for email in re.findall(regexp.EMAIL, content):  # Remove potentially sensitive emails
            content = content.replace(email, 'email-removed@provider.com')

        Proof.objects.create(
            content=content,
            ticket=self.ticket,
        )

    @rule_action()
    def add_email_body_as_proof(self, flush_proof=True):
        """
        """
        if flush_proof:
            self.ticket.proof.all().delete()

        # Add proof
        content = self.report.body

        for email in re.findall(regexp.EMAIL, content):  # Remove potentially sensitive emails
            content = content.replace(email, 'email-removed@provider.com')

        Proof.objects.create(
            content=content,
            ticket=self.ticket,
        )

    @rule_action()
    def set_ticket_phishtocheck(self):
        """
        """
        self.report.status = 'PhishToCheck'
        self.report.save()
        utils.push_notification({
            'type': 'new phishToCheck',
            'id': self.report.id,
            'message': 'New PhishToCheck report %d' % (self.report.id),
        })

    @rule_action(params=[{'fieldType': FIELD_NUMERIC, 'name': 'seconds'}])
    def set_ticket_timeout(self, seconds):
        """
        """
        if not self.existing_ticket:
            self.ticket.previousStatus = self.ticket.status
            self.ticket.status = 'WaitingAnswer'
            self.ticket.snoozeDuration = seconds
            self.ticket.snoozeStart = datetime.now()
            self.ticket.save()
            utils.scheduler.enqueue_in(
                timedelta(seconds=seconds),
                'ticket.timeout',
                ticket_id=self.ticket.id,
                timeout=3600,
            )

    @rule_action()
    def phishing_block_url_and_mail(self):
        """
        """
        phishing.block_url_and_mail(
            ticket_id=self.ticket,
            report_id=self.report
        )

    @rule_action()
    def phishing_close_because_all_down(self):
        """
        """
        phishing.close_because_all_down(report=self.report)

    @rule_action()
    def do_nothing(self):
        """
        """
        pass
