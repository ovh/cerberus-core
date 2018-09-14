
from .action import ActionService
from .crm import CRMService
from .email import EmailService
from .kpi import KPIService
from .phishing import PhishingService
from .reputation import ReputationService
from .search import SearchService
from .storage import StorageService

SERVICES_TO_SETUP = (
    ActionService,
    CRMService,
    EmailService,
    KPIService,
    PhishingService,
    ReputationService,
    SearchService,
    StorageService,
)


def setup_services(app):

    for service in SERVICES_TO_SETUP:
        service.set_up(app)
