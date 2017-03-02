# -*- coding: utf-8 -*-

"""
    Business rules for new Cerberus Ticket email answer
"""

import json

from utils import utils
from worker.common import CDN_REQUEST_LOCK, CDN_REQUEST_REDIS_QUEUE
from worker.workflows.engine.fields import FIELD_TEXT
from worker.workflows.engine.variables import (boolean_rule_variable,
                                               string_rule_variable,
                                               BaseVariables)


class EmailReplyVariables(BaseVariables):
    """
        This class implements variables getters for EmailReply `abuse.models.BusinessRules`
    """
    def __init__(self, ticket, abuse_report, recipient, category):
        """
            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `worker.parsing.parsed.ParsedEmail` abuse_report: the email
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
        return check_if_ticket_in_cache(self.ticket.id, provider)


@utils.redis_lock(CDN_REQUEST_LOCK)
def check_if_ticket_in_cache(ticket_id, provider):
    """
        Check if the answered ticket is in the request cache
    """
    for entry in utils.redis.lrange(CDN_REQUEST_REDIS_QUEUE % provider, 0, -1):
        entry = json.loads(entry)
        if int(entry['request_ticket_id']) == int(ticket_id):
            return True

    return False
