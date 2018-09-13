# -*- coding: utf-8 -*-

"""
    Business rules for new Cerberus Ticket email answer
"""

from ...engine.fields import FIELD_TEXT
from ...engine.variables import (boolean_rule_variable,
                                 string_rule_variable,
                                 BaseVariables)
from ...variables import CDNRequestVariables


class DefaultEmailReplyVariables(BaseVariables):
    """
        This class implements variables getters for
        EmailReply `abuse.models.BusinessRules`
    """
    def __init__(self, ticket, abuse_report, recipient, category):
        """
            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `cerberus.parsers.ParsedEmail` abuse_report: the email
            :param str recipient: The recipient of the answer
            :param str category: defendant, plaintiff or other
        """
        self.ticket = ticket
        self.parsed_email = abuse_report
        self.email_recipient = recipient
        self.email_category = category

    @string_rule_variable()
    def category(self):
        """
        """
        return self.email_category.lower()

    @string_rule_variable()
    def email_sender(self):
        """
        """
        return self.parsed_email.provider.lower()

    @string_rule_variable()
    def email_body(self):
        """
        """
        return self.parsed_email.body

    @string_rule_variable()
    def email_subject(self):
        """
        """
        return self.parsed_email.subject

    @boolean_rule_variable(params=[{'fieldType': FIELD_TEXT, 'name': 'provider'}])
    def ticket_in_cdn_cache(self, provider):
        """
        """
        return CDNRequestVariables.is_existing_request(
            self.ticket.id, provider
        )
