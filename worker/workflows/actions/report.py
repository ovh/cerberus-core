# -*- coding: utf-8 -*-

"""
    Actions for Report rules
"""

import re
from datetime import datetime, timedelta

from abuse.models import Proof
from django.conf import settings
from factory.implementation import ImplementationFactory as implementations
from utils import utils
from worker.parsing import regexp
from worker.workflows.engine.actions import rule_action, BaseActions
from worker.workflows.engine.fields import (FIELD_TEXT,
                                            FIELD_NO_INPUT,
                                            FIELD_NUMERIC)
from worker import common, database, phishing, ticket


class ReportActions(BaseActions):
    """
        This class implements usefull actions required for Report `abuse.models.BusinessRules`
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

    @rule_action()
    def attach_report_to_ticket(self):
        """
        """
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
        from worker import Logger
        Logger.debug(resolution)
        Logger.debug(settings.CODENAMES[resolution])
        common.close_ticket(
            self.ticket,
            resolution_codename=settings.CODENAMES[resolution]
        )
        self.ticket.update = keep_update
        self.ticket.save()

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

    @rule_action(params=[{'fieldType': FIELD_TEXT, 'name': 'template_codename'}])
    def send_defendant_email(self, template_codename=None):
        """
        """
        common.send_email(
            self.ticket,
            [self.report.defendant.details.email],
            template_codename,
            lang=self.report.defendant.details.lang,
            acknowledged_report_id=self.report.id
        )

        common.set_ticket_status(self.ticket, 'WaitingAnswer')
        self.ticket.snoozeDuration = 172800
        self.ticket.snoozeStart = datetime.now()
        self.ticket.save()

    @rule_action()
    def close_defendant(self):
        """
            Breach of contract
        """
        implementations.instance.get_singleton_of(
            'ActionServiceBase'
        ).close_defendant(
            ticket=self.ticket
        )

    @rule_action()
    def close_all_services(self):
        """
            Close all ̀`abuse.models.Defendant` `abuse.models.Service`
        """
        implementations.instance.get_singleton_of(
            'ActionServiceBase'
        ).close_all_services(
            ticket=self.ticket
        )

    @rule_action()
    def close_service(self):
        """
            Close `abuse.models.Ticket` `abuse.models.Service`
        """
        implementations.instance.get_singleton_of(
            'ActionServiceBase'
        ).close_service(
            ticket=self.ticket
        )

    @rule_action()
    def block_outbound_emails(self):
        """
            Disallow outbound emails for `abuse.models.Ticket` related `abuse.models.Service`
        """
        implementations.instance.get_singleton_of(
            'ActionServiceBase'
        ).block_outbound_emails(
            ticket=self.ticket
        )

    @rule_action()
    def apply_timeout_action(self):
        """
        """
        ticket.timeout(self.ticket.id)

    @rule_action(params=[{'fieldType': FIELD_TEXT, 'name': 'regex'},
                         {'fieldType': FIELD_NO_INPUT, 'name': 'multiline'},
                         {'fieldType': FIELD_NO_INPUT, 'name': 'dehtmlify'},
                         {'fieldType': FIELD_NO_INPUT, 'name': 'flush_proof'}])
    def add_email_body_regex_proof(self, regex, multiline=False, dehtmlify=True, flush_proof=True):
        """
        """
        flags = [re.MULTILINE] if multiline else []

        content = self.report.body
        if dehtmlify:
            content = utils.dehtmlify(content)

        try:
            content = re.search(regex, content, *flags).group()
        except AttributeError:
            raise AttributeError('Unable to find given regex in email body')

        if flush_proof:
            self.ticket.proof.all().delete()

        for email in re.findall(regexp.EMAIL, content):  # Remove potentially sensitive emails
            content = content.replace(email, 'email-removed@provider.com')

        Proof.objects.create(
            content=content,
            ticket=self.ticket,
        )

    @rule_action(params=[{'fieldType': FIELD_NO_INPUT, 'name': 'flush_proof'}])
    def add_email_body_as_proof(self, flush_proof=True):
        """
        """
        if flush_proof:
            self.ticket.proof.all().delete()

        # Add proof
        content = utils.dehtmlify(self.report.body)

        for email in re.findall(regexp.EMAIL, content):  # Remove potentially sensitive emails
            content = content.replace(email, 'email-removed@provider.com')

        Proof.objects.create(
            content=content,
            ticket=self.ticket,
        )

    @rule_action(params=[{'fieldType': FIELD_TEXT, 'name': 'status'}])
    def set_report_status(self, status):
        """
        """
        self.report.status = status
        self.report.save()

    @rule_action(params=[{'fieldType': FIELD_TEXT, 'name': 'status'}])
    def set_ticket_status(self, status):
        """
        """
        self.ticket.status = status
        self.ticket.save()

    @rule_action(params=[{'fieldType': FIELD_TEXT, 'name': 'priority'}])
    def set_ticket_priority(self, priority):
        """
        """
        self.ticket.priority = priority
        self.ticket.save()

    @rule_action(params=[{'fieldType': FIELD_NUMERIC, 'name': 'days'}])
    def set_report_timeout(self, days):
        """
        """
        utils.scheduler.enqueue_in(
            timedelta(days=days),
            'report.archive_if_timeout',
            report_id=self.report.id
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
            if self.ticket.status != 'WaitingAnswer':
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
