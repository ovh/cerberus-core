# -*- coding: utf-8 -*-

"""
    Business rules for new CDN Request
"""

from ...engine.fields import FIELD_TEXT
from ...engine.variables import (boolean_rule_variable,
                                 BaseVariables)
from ....utils import networking


class DefaultCDNRequestVariables(BaseVariables):
    """
        This class implements variables getters
        for EmailReply `abuse.models.BusinessRules`
    """
    redis_queue = 'cdnrequest:{}:request'

    def __init__(self, domain_to_request):
        """
        """
        self.ips = networking.get_ips_from_fqdn(domain_to_request)

    @boolean_rule_variable(params=[
        {'fieldType': FIELD_TEXT, 'name': 'provider'}
    ])
    def provider_ips_owner(self, provider):
        """
        """
        for ip_addr in self.ips:
            if networking.get_ip_network(ip_addr) == provider:
                return True
        return False
