from .categories import category_views
from .defendants import defendant_views
from .emailtemplates import email_templates_views
from .misc import misc_views
from .news import news_views
from .presets import preset_views
from .providers import provider_views
from .reports import report_views
from .reputations import reputation_views
from .tags import tag_views
from .tickets import ticket_views
from .thresholds import threshold_views

views_to_register = (
    category_views,
    defendant_views,
    email_templates_views,
    misc_views,
    news_views,
    preset_views,
    provider_views,
    report_views,
    reputation_views,
    tag_views,
    ticket_views,
    threshold_views,
)
