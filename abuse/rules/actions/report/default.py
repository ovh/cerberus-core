# -*- coding: utf-8 -*-

"""
    Actions for Report rules
"""

import re
from datetime import datetime, timedelta

from ...engine.actions import rule_action, BaseActions
from ...engine.fields import FIELD_TEXT, FIELD_NO_INPUT, FIELD_NUMERIC
from ....models import Ticket, History, Proof, ServiceAction
from ....parsers import Parser
from ....tasks import action, enqueue_in, helpers, phishing
from ....services import ActionService, PhishingService
from ....utils import cache, text


class NoServiceActionScheduled(Exception):
    """
        raised when `ReportActions.schedule_service_action`
        fails to schedule action
    """

    def __init__(self, message):
        super(NoServiceActionScheduled, self).__init__(message)


class DefaultReportActions(BaseActions):
    """
        This class implements usefull actions required
        for Report `abuse.models.BusinessRules`
    """

    def __init__(self, report, cerberus_ticket, ack_lang="EN"):
        """
            :param `abuse.models.Report` report: A Cerberus report instance
            :param `abuse.models.Ticket` cerberus_ticket: A ticket instance
            :param str ack_lang: Langage to use for report acknowledgement
        """
        self.report = report
        self.ticket = cerberus_ticket
        self.ack_lang = ack_lang
        self.existing_ticket = bool(cerberus_ticket)

    @rule_action(
        params=[
            {"fieldType": FIELD_NO_INPUT, "name": "create_new"},
            {"fieldType": FIELD_NO_INPUT, "name": "attach_new"},
        ]
    )
    def create_ticket(self, create_new=False, attach_new=True):
        """
        """
        if create_new or not self.ticket:
            self.ticket = Ticket.create_ticket(
                self.report.defendant,
                self.report.category,
                self.report.service,
                attach_new=attach_new,
            )

        self.report.ticket = self.ticket
        self.report.status = "Attached"
        self.report.save()

        History.log_ticket_action(
            ticket=self.ticket,
            action="attach_report",
            report=self.report,
            new_ticket=not self.existing_ticket,
        )
        self.ticket.set_higher_priority()

    @rule_action()
    def attach_report_to_ticket(self):
        """
        """
        self.report.ticket = self.ticket
        self.report.status = "Attached"
        self.report.save()

        History.log_ticket_action(
            ticket=self.ticket,
            action="attach_report",
            report=self.report,
            new_ticket=not self.existing_ticket,
        )
        self.ticket.set_higher_priority()

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
            {"fieldType": FIELD_TEXT, "name": "lang"},
        ]
    )
    def send_provider_ack(self, template_codename="ack_report_received", lang=None):
        """
        """
        _lang = lang or self.ack_lang or "EN"
        report_tags = self.report.provider.tags.all().values_list("name", flat=True)
        if "never_auto_ack" not in report_tags:
            helpers.send_email(
                self.ticket,
                [self.report.provider.email],
                template_codename,
                lang=_lang,
                acknowledged_report_id=self.report.id,
            )

    @rule_action(params=[{"fieldType": FIELD_TEXT, "name": "template_codename"}])
    def send_defendant_email(
        self, template_codename=None, snooze_duration=172800, force_snooze=False
    ):
        """
        """
        helpers.send_email(
            self.ticket,
            [self.report.defendant.details.email],
            template_codename,
            lang=self.report.defendant.details.lang,
            acknowledged_report_id=self.report.id,
        )

        if force_snooze:
            self.ticket.snoozeDuration = snooze_duration
            self.ticket.snoozeStart = datetime.now()
            self.ticket.set_status("WaitingAnswer")
        else:
            if not any((self.ticket.snoozeDuration, self.ticket.snoozeStart)):
                self.ticket.snoozeDuration = snooze_duration
                self.ticket.snoozeStart = datetime.now()
                if self.ticket.status != "WaitingAnswer":
                    self.ticket.set_status("WaitingAnswer")

        self.ticket.save(update_fields=["snoozeDuration", "snoozeStart"])

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
            lang = self.report.defendant.details.lang

        helpers.send_email(
            self.ticket,
            [email],
            template_codename,
            lang=lang,
            acknowledged_report_id=self.report.id,
        )

    @rule_action()
    def close_defendant(self):
        """
            Breach of contract
        """
        ActionService.close_defendant(ticket=self.ticket)

    @rule_action()
    def close_all_services(self):
        """
            Close all ̀`abuse.models.Defendant` `abuse.models.Service`
        """
        ActionService.close_all_services(ticket=self.ticket)

    @rule_action()
    def close_service(self):
        """
            Close `abuse.models.Ticket` `abuse.models.Service`
        """
        ActionService.close_service(ticket=self.ticket)

    @rule_action(
        params=[
            {"fieldType": FIELD_TEXT, "name": "regex"},
            {"fieldType": FIELD_NO_INPUT, "name": "multiline"},
            {"fieldType": FIELD_NO_INPUT, "name": "dehtmlify"},
            {"fieldType": FIELD_NO_INPUT, "name": "flush_proof"},
        ]
    )
    def add_email_body_regex_proof(
        self, regex=None, multiline=False, dehtmlify=True, flush_proof=True
    ):
        """
        """
        flags = [re.MULTILINE] if multiline else []

        content = self.report.body
        if dehtmlify:
            content = text.dehtmlify(content)

        try:
            content = re.search(regex, content, *flags).group()
        except AttributeError:
            raise AttributeError("Unable to find given regex in email body")

        if flush_proof:
            self.ticket.proof.all().delete()

        # Remove potentially sensitive emails
        for email in re.findall(Parser.email_re, content):
            content = content.replace(email, "email-removed@provider.com")

        Proof.create(content=content, ticket=self.ticket)

    @rule_action(params=[{"fieldType": FIELD_NO_INPUT, "name": "flush_proof"}])
    def add_email_body_as_proof(self, flush_proof=True):
        """
        """
        if flush_proof:
            self.ticket.proof.all().delete()

        # Add proof
        content = text.dehtmlify(self.report.body)

        # Remove potentially sensitive emails
        for email in re.findall(Parser.email_re, content):
            content = content.replace(email, "email-removed@provider.com")

        Proof.create(content=content, ticket=self.ticket)

    @rule_action(
        params=[
            {"fieldType": FIELD_TEXT, "name": "item_type"},
            {"fieldType": FIELD_NO_INPUT, "name": "flush_proof"},
        ]
    )
    def add_items_as_proof(self, item_type=None, flush_proof=True):
        """
        """
        if flush_proof:
            self.ticket.proof.all().delete()

        # Add proof
        items = (
            self.report.reportItemRelatedReport.filter(itemType=item_type)
            .values_list("rawItem", flat=True)
            .distinct()
        )

        if not items:
            raise AssertionError("No items found for function add_items_as_proof")

        content = "\n".join(items)

        # Remove potentially sensitive emails
        for email in re.findall(Parser.email_re, content):
            content = content.replace(email, "email-removed@provider.com")

        Proof.create(content=content, ticket=self.ticket)

    @rule_action(params=[{"fieldType": FIELD_TEXT, "name": "status"}])
    def set_report_status(self, status):
        """
        """
        if status != self.report.status:
            self.report.status = status
            self.report.save(update_fields=["status"])

    @rule_action(params=[{"fieldType": FIELD_TEXT, "name": "status"}])
    def set_ticket_status(self, status):
        """
        """
        if status != self.ticket.status:
            self.ticket.set_status(status)

    @rule_action(params=[{"fieldType": FIELD_TEXT, "name": "priority"}])
    def set_ticket_priority(self, priority):
        """
        """
        self.ticket.priority = priority
        self.ticket.save(update_fields=["priority"])

    @rule_action()
    def set_ticket_moderation(self):
        """
        """
        self.ticket.moderation = True
        self.ticket.save(update_fields=["moderation"])

    @rule_action()
    def set_ticket_escalated(self):
        """
        """
        self.ticket.escalated = True
        self.ticket.save(update_fields=["escalated"])

    @rule_action()
    def set_ticket_alarm(self):
        """
        """
        self.ticket.alarm = True
        self.ticket.save(update_fields=["alarm"])

    @rule_action(params=[{"fieldType": FIELD_NUMERIC, "name": "days"}])
    def set_report_timeout(self, days):
        """
        """
        enqueue_in(
            timedelta(days=days), "report.archive_if_timeout", report_id=self.report.id
        )

    @rule_action()
    def set_ticket_phishtocheck(self):
        """
        """
        self.report.status = "PhishToCheck"
        self.report.save(update_fields=["status"])
        cache.push_notification(
            {
                "type": "new phishToCheck",
                "id": self.report.id,
                "message": "New PhishToCheck report %d" % (self.report.id),
            }
        )

    @rule_action(
        params=[
            {"fieldType": FIELD_NO_INPUT, "name": "description"},
            {"fieldType": FIELD_NO_INPUT, "name": "close_ticket"},
        ]
    )
    def schedule_service_action(self, description, close_ticket=True):
        """
            Schedule action on defendant service

            :param list description: description of action to apply based
                                     on defendant/service specificities
            :param boolean close_ticket: close ticket after
                                         service action execution
        """
        ips = self.report.get_attached_ipaddr()
        if len(ips) != 1:
            raise NoServiceActionScheduled(
                "Can't get IP address for action ( {} ip(s))".format(len(ips))
            )

        ip_addr = ips[0]

        # Order matters
        # defendant and service objects values are regex based
        for desc in description:

            defendant_match = self._defendant_match(desc["defendant"])
            if not defendant_match:
                continue

            for action_desc in desc["service_delay_action"]:

                service_match = self._service_match(action_desc["service"])
                if not service_match:
                    continue

                _action = ServiceAction.get(
                    module=action_desc["action"]["module"],
                    level=action_desc["action"]["level"],
                )

                action.schedule_action(
                    ticket=self.ticket,
                    action=_action,
                    ip_addr=ip_addr,
                    seconds=action_desc["delay"],
                    close_ticket=close_ticket,
                )
                return

        # No action scheduled -> ActionError
        self.ticket.set_status("ActionError")

        self.ticket.add_comment(
            "Action for this defendant/service not found in rule description"
        )

    def _defendant_match(self, params_defendant_regex):

        attributes_to_check = ("legal_form", "country")
        current_defendant_values = {
            "country": self.report.defendant.details.country,
            "legal_form": self.report.defendant.details.legalForm,
        }

        return all_match(
            attributes_to_check, params_defendant_regex, current_defendant_values
        )

    def _service_match(self, params_service_regex):

        attributes_to_check = ("type", "reference")
        current_service_values = {
            "type": self.report.service.componentType,
            "reference": self.report.service.reference,
        }

        return all_match(
            attributes_to_check, params_service_regex, current_service_values
        )

    @rule_action()
    def block_report_url(self):
        """
        """
        items = self.report.reportItemRelatedReport.filter(itemType="URL")

        for item in items:
            PhishingService.block_url(item.rawItem, item.report)

    @rule_action()
    def phishing_close_because_all_down(self):
        """
        """
        phishing.close_because_all_down(report=self.report)

    @rule_action(params=[{"fieldType": FIELD_TEXT, "name": "tag_name"}])
    def add_report_tag(self, tag_name):

        self.report.add_tag(tag_name)

    @rule_action(
        params=[
            {"fieldType": FIELD_TEXT, "name": "task_name"},
            {"fieldType": FIELD_NUMERIC, "name": "seconds"},
            {"fieldType": FIELD_NO_INPUT, "name": "task_params"},
        ]
    )
    def enqueue_report_task(self, task_name=None, seconds=60, task_params=None):
        """
        """
        if not task_name:
            raise ValueError('missing "task_name" param')

        if not task_params:
            task_params = {}

        enqueue_in(
            timedelta(seconds=seconds),
            task_name,
            report_id=self.report.id,
            **task_params
        )

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

    @rule_action()
    def do_nothing(self):
        """
        """
        pass


def all_match(attribs_to_check, expressions, values):
    """
        For each attributes, check if expressions match values
    """
    matches = []

    for attrib in attribs_to_check:
        regex = expressions.get(attrib)
        if regex and attrib in values:
            matches.append(re.match(regex, values[attrib], re.I))

    return all(matches)
