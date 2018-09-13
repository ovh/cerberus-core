
from .base import SearchServiceBase


class DefaultDummyService(SearchServiceBase):

    def __init__(self, config, logger=None):
        pass

    def index_email(self, *args, **kwargs):
        pass

    def search_reports(self, *args, **kwargs):
        pass
