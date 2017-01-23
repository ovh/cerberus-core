# -*- coding: utf-8 -*-

"""
    Business rules for new abuse report
"""


from datetime import datetime, timedelta

from abuse.models import Report, Ticket
from config import settings
from worker import database, phishing
from worker.workflows.engine.fields import FIELD_NUMERIC
from worker.workflows.engine.variables import (numeric_rule_variable, boolean_rule_variable,
                                               select_multiple_rule_variable, string_rule_variable,
                                               select_rule_variable, BaseVariables)


class ReportVariables(BaseVariables):
    """
        This class implements variables getters for Report `abuse.models.BusinessRules`
    """
    def __init__(self, parsed_email, report, ticket, is_trusted=False):
        """
            :param `worker.parsing.parser import ParsedEmail` email_report: The parsed abuse report
            :param `abuse.models.Report` report: A Cerberus report instance
            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param bool is_trusted: if the report is trusted
        """
        if not isinstance(is_trusted, bool):
            is_trusted = False

        recipients = []
        self.trusted = report.provider.trusted or is_trusted
        self.existing_ticket = bool(ticket)

        if parsed_email:
            recipients = parsed_email.recipients
            self.trusted = parsed_email.trusted or self.trusted

        self.parsed_email = parsed_email
        self.report = report
        self.ticket = ticket
        self.attibutes_tags = database.get_tags(
            report.provider,
            recipients,
            report.subject,
            report.body
        )

    @boolean_rule_variable()
    def has_ticket(self):
        """
        """
        return self.existing_ticket

    @boolean_rule_variable()
    def is_report_trusted(self):
        """
        """
        return self.trusted

    @string_rule_variable()
    def report_category(self):
        """
        """
        return self.report.category.name.lower()

    @select_multiple_rule_variable()
    def report_provider(self):
        """
        """
        return [self.report.provider.email.lower()]

    @string_rule_variable()
    def report_body(self):
        """
        """
        return self.report.body

    @boolean_rule_variable()
    def has_urls(self):
        """
        """
        return self.report.reportItemRelatedReport.filter(
            itemType='URL'
        ).exists()

    @boolean_rule_variable()
    def avoid_phishtocheck(self):
        """
        """
        for tag in self.attibutes_tags:
            if tag.tagType == 'Provider' and tag.name == settings.TAGS['no_phishtocheck']:
                return True
        return False

    @boolean_rule_variable()
    def autoarchive(self):
        """
        """
        for tag in self.attibutes_tags:
            if tag.tagType == 'Provider' and tag.name == settings.TAGS['autoarchive']:
                return True
        return False

    @boolean_rule_variable()
    def urls_down(self):
        """
        """
        if not self.has_urls():
            return False

        return phishing.check_if_all_down(report=self.report)

    @boolean_rule_variable()
    def all_items_phishing(self):
        """
            Returns if all items for given report are clearly phishing items,
            based on 'ping_url' service

            :param `abuse.models.Report` report: A Cerberus report instance
            :return: If all items are clearly phishing items
            :rtype: bool
        """
        result = set()

        for item in self.report.reportItemRelatedReport.filter(itemType='URL'):
            is_phishing = database.get_item_status_phishing(item.id, last=1)
            for res in is_phishing:
                result.add(res)

        response = False
        if len(result) == 1 and True in result:
            response = True

        return response

    @boolean_rule_variable()
    def has_defendant(self):
        """
        """
        return bool(self.report.defendant)

    @numeric_rule_variable()
    def customer_since(self):
        """
            Get defendant age

            :return: defendant age in days
            :rtype: int
        """
        return self.report.defendant.details.creationDate >= datetime.now()

    @string_rule_variable()
    def defendant_legal_form(self):
        """
        """
        return self.report.defendant.details.legalForm

    @select_rule_variable()
    def defendant_country(self):
        """
        """
        return [self.report.defendant.details.country]

    @numeric_rule_variable()
    def report_count(self):
        """
        """
        return Report.objects.filter(
            defendant=self.report.defendant
        ).count()

    @numeric_rule_variable()
    def ticket_count(self):
        """
        """
        return Ticket.objects.filter(
            defendant=self.report.defendant
        ).count()

    @numeric_rule_variable()
    def service_action_count(self):
        """
        """
        return Ticket.objects.filter(
            defendant=self.report.defendant
        ).values_list('jobs').count()

    @numeric_rule_variable(params=[{'fieldType': FIELD_NUMERIC, 'name': 'last_days'}])
    def service_action_count_last_days(self, last_days=30):
        """
        """
        return Ticket.objects.filter(
            jobs__executionDate__gte=datetime.now() - timedelta(days=last_days),
            defendant=self.report.defendant
        ).values_list('jobs').count()
