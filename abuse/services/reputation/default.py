
from .base import ReputationServiceBase


class DefaultDummyService(ReputationServiceBase):
    def __init__(self, config, logger=None):
        pass

    def get_ip_rbl_reputations(self, ip_addr):
        pass

    def get_ip_external_reputations(self, ip_addr):
        pass

    def get_ip_external_details(self, ip_addr, short_name):
        pass

    def get_url_external_reputations(self, url):
        pass

    def get_ip_internal_reputations(self, ip_addr):
        pass

    def get_ip_tools(self, ip_addr):
        pass
