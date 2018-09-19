# -*- coding: utf-8 -*-

"""
    Default variable for an abuse report
"""


from datetime import datetime, timedelta

from django.db.models import Q

from ...engine.fields import FIELD_NO_INPUT, FIELD_NUMERIC, FIELD_TEXT
from ...engine.variables import (
    numeric_rule_variable,
    boolean_rule_variable,
    select_multiple_rule_variable,
    string_rule_variable,
    BaseVariables,
)
from ....models import (
    BusinessRulesHistory,
    EmailFilterTag,
    Report,
    Ticket,
    ReportThreshold,
)
from ....services import CRMService, PhishingService
from ....services.phishing import PhishingServiceException


def now():
    """
        Because of error

        "can't set attributes of built-in/extension type 'datetime.datetime'"

        when mocking datetime.datetime.now() in tests
    """
    return datetime.now()


class DefaultReportVariables(BaseVariables):
    """
        This class implements Report variables getters
        for rules engine
    """

    def __init__(self, parsed_email, report, ticket, is_trusted=False):
        """
            :param `cerberus.parsers.ParsedEmail` parsed_email: The parsed email
            :param `abuse.models.Report` report: A Cerberus report instance
            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param bool is_trusted: if the report is trusted
        """
        if not isinstance(is_trusted, bool):
            is_trusted = False

        self.recipients = []
        self.trusted = report.provider.trusted or is_trusted
        self.existing_ticket = bool(ticket)

        if parsed_email:
            self.recipients = parsed_email.recipients
            self.email_headers = parsed_email.headers

        self.report = report
        self.ticket = ticket
        self.attibutes_tags = EmailFilterTag.get_tags_for_email(
            report.provider, self.recipients, report.subject, report.body
        )

    @boolean_rule_variable()
    def has_ticket(self):
        """
            Check if there already an existing `abuse.models.Ticket`

            :return: is there is an existing ticket
            :rtype: bool
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

    @select_multiple_rule_variable()
    def report_recipients(self):
        """
        """
        return self.recipients

    @string_rule_variable()
    def report_body(self):
        """
        """
        return self.report.body

    @string_rule_variable()
    def report_subject(self):
        """
        """
        return self.report.subject

    @boolean_rule_variable()
    def has_fqdn(self):
        """
        """
        return self.report.reportItemRelatedReport.filter(itemType="FQDN").exists()

    @boolean_rule_variable()
    def has_urls(self):
        """
        """
        return self.report.reportItemRelatedReport.filter(itemType="URL").exists()

    @boolean_rule_variable()
    def avoid_phishtocheck(self):
        """
        """
        for tag in self.attibutes_tags:
            if tag.tagType == "Provider" and tag.name == "distrust:2:no_phishtocheck":
                return True
        return False

    @boolean_rule_variable()
    def autoarchive(self):
        """
        """
        for tag in self.attibutes_tags:
            if tag.tagType == "Provider" and tag.name == "distrust:0:autoarchive":
                return True
        return False

    @boolean_rule_variable(
        params=[
            {"fieldType": FIELD_NO_INPUT, "name": "try_screenshot"},
            {"fieldType": FIELD_NUMERIC, "name": "down_threshold"},
        ]
    )
    def urls_down(self, try_screenshot=True, down_threshold=75):
        """
        """
        if not self.has_urls():
            return False

        country = "FR"
        if self.report.defendant:
            country = self.report.defendant.details.country

        results = []
        for url in self.report.get_attached_urls():
            try:
                response = ping_url(url, try_screenshot, country)
                results.append(response.score)
            except PhishingServiceException:
                results.append(0)

        return all([score >= down_threshold for score in results])

    @boolean_rule_variable()
    def all_items_phishing(self):
        """
            Returns if all items for given report are clearly phishing items,
            based on 'ping_url' service

            :param `abuse.models.Report` report: A Cerberus report instance
            :return: If all items are clearly phishing items
            :rtype: bool
        """
        country = "FR"
        if self.report.defendant:
            country = self.report.defendant.details.country

        results = set()
        for url in self.report.get_attached_urls():
            try:
                response = ping_url(url, False, country)
                results.add(response.is_phishing)
            except PhishingServiceException:
                results.add(False)

        response = False
        if results and all(results):
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
        return (now() - self.report.defendant.details.creationDate).days

    @select_multiple_rule_variable()
    def defendant_legal_form(self):
        """
        """
        return [self.report.defendant.details.legalForm]

    @boolean_rule_variable()
    def defendant_is_vip(self):
        """
        """
        return self.report.defendant.details.isVIP

    @boolean_rule_variable()
    def defendant_is_internal(self):
        """
        """
        return self.report.defendant.details.isInternal

    @select_multiple_rule_variable()
    def defendant_country(self):
        """
        """
        return [self.report.defendant.details.country.upper()]

    @numeric_rule_variable()
    def report_count(self):
        """
        """
        return Report.filter(
            ~Q(status="Archived"), defendant=self.report.defendant
        ).count()

    @boolean_rule_variable()
    def report_ticket_threshold(self):
        """
        """
        thres = ReportThreshold.filter(category=self.report.category).last()
        if not thres:
            return False

        reports_count = Report.filter(
            defendant=self.report.defendant,
            service=self.report.service,
            category=self.report.category,
            status="New",
            receivedDate__gte=now() - timedelta(days=thres.interval),
        ).count()
        return reports_count >= thres.threshold

    @numeric_rule_variable(
        params=[
            {"fieldType": FIELD_NO_INPUT, "name": "same_service"},
            {"fieldType": FIELD_TEXT, "name": "last_days"},
            {"fieldType": FIELD_NO_INPUT, "name": "open_only"},
        ]
    )
    def ticket_count(self, same_service=False, last_days=None, open_only=True):
        """
        """
        query = Q(defendant=self.report.defendant)
        if self.ticket:
            query &= ~Q(id=self.ticket.id)

        if open_only:
            query &= ~Q(status="Closed")

        if last_days:
            query &= Q(creationDate__gte=now() - timedelta(days=last_days))

        if same_service:
            query &= Q(service=self.report.service)

        return Ticket.filter(query).count()

    @boolean_rule_variable(
        params=[
            {"fieldType": FIELD_NO_INPUT, "name": "same_service"},
            {"fieldType": FIELD_TEXT, "name": "last_days"},
            {"fieldType": FIELD_TEXT, "name": "rule_codename"},
        ]
    )
    def has_defendant_answers(
        self, same_service=False, last_days=None, rule_codename=None
    ):

        query = Q(defendant=self.report.defendant)
        if last_days:
            delta = timedelta(days=last_days)
            query &= Q(businessruleshistory__date__gte=now() - delta)

        if same_service:
            query &= Q(service=self.report.service)

        if rule_codename:
            query &= Q(businessruleshistory__businessRules__name=rule_codename)

        reports = Report.filter(query).distinct()
        tickets = Ticket.filter(reportTicket__in=reports).distinct()

        if not tickets:
            return False

        return all([t.has_defendant_email_responses() for t in tickets])

    @select_multiple_rule_variable()
    def service_type(self):
        """
        """
        return [self.report.service.componentType.lower()]

    @numeric_rule_variable()
    def service_action_count(self):
        """
        """
        return (
            Ticket.filter(defendant=self.report.defendant).values_list("jobs").count()
        )

    @numeric_rule_variable(params=[{"fieldType": FIELD_NUMERIC, "name": "last_days"}])
    def service_action_count_last_days(self, last_days=30):
        """
        """
        return (
            Ticket.filter(
                jobs__executionDate__gte=now() - timedelta(days=last_days),
                defendant=self.report.defendant,
            )
            .values_list("jobs")
            .count()
        )

    @numeric_rule_variable(
        params=[
            {"fieldType": FIELD_TEXT, "name": "rule_codename"},
            {"fieldType": FIELD_NUMERIC, "name": "since_last_days"},
            {"fieldType": FIELD_NUMERIC, "name": "older_than_days"},
        ]
    )
    def rule_applied(
        self, rule_codename=None, since_last_days=None, older_than_days=None
    ):
        """
        """
        query = Q(defendant=self.report.defendant)
        query &= Q(service=self.report.service)

        if rule_codename:
            query &= Q(businessRules__name=rule_codename)

        if since_last_days:
            query &= Q(date__gte=now() - timedelta(days=since_last_days))

        if older_than_days:
            query &= Q(date__lte=now() - timedelta(days=older_than_days))

        return BusinessRulesHistory.filter(query).count()

    @boolean_rule_variable(
        params=[
            {"fieldType": FIELD_TEXT, "name": "min_date"},
            {"fieldType": FIELD_TEXT, "name": "max_date"},
        ]
    )
    def report_received_beetween(self, min_date=None, max_date=None):
        """
        """
        min_date = datetime.strptime(min_date, "%Y-%m-%d %H:%M")
        max_date = datetime.strptime(max_date, "%Y-%m-%d %H:%M")

        if min_date < self.report.receivedDate < max_date:
            return True
        return False

    @numeric_rule_variable()
    def defendant_revenue(self):

        return CRMService.get_customer_revenue(
            self.report.defendant.customerId, service=self.report.service.name
        )

    @select_multiple_rule_variable()
    def defendant_customer_id(self):
        """
        """
        return [self.report.defendant.customerId.lower()]


def ping_url(url, try_screenshot=True, country="FR"):

    return PhishingService.ping_url(url, country=country, try_screenshot=try_screenshot)
