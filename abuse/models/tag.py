
from django.db.models import SmallIntegerField

from .base import CerberusModel
from .helpers import TruncatedCharField


class Tag(CerberusModel):
    """
        A way to filter / add extra infos to Cerberus main classes :

        - `abuse.models.Defendant`
        - `abuse.models.Ticket`
        - `abuse.models.Report`
        - `abuse.models.Provider`
        - `abuse.models.News`
    """

    TAG_TYPE = (
        ("Defendant", "Defendant"),
        ("Ticket", "Ticket"),
        ("Report", "Report"),
        ("Provider", "Provider"),
        ("News", "News"),
    )
    codename = TruncatedCharField(null=False, max_length=256, editable=False)
    name = TruncatedCharField(null=False, max_length=255)
    tagType = TruncatedCharField(max_length=32, null=False, choices=TAG_TYPE)
    level = SmallIntegerField(null=False, default=0)
