
from django.db.models import (
    DateTimeField,
    GenericIPAddressField,
    ForeignKey,
    IntegerField,
    BooleanField,
)

from .base import CerberusModel
from .helpers import TruncatedCharField


class ReportItem(CerberusModel):
    """
        Fraudulent item found in a `abuse.models.Report`
    """

    ITEM_TYPE = (("IP", "Ip"), ("FQDN", "Fqdn"), ("URL", "Url"))

    report = ForeignKey("Report", null=False, related_name="reportItemRelatedReport")

    rawItem = TruncatedCharField(db_index=True, max_length=4095)
    itemType = TruncatedCharField(max_length=4, null=True, choices=ITEM_TYPE)
    fqdn = TruncatedCharField(null=True, max_length=255)
    fqdnResolved = GenericIPAddressField(db_index=True, null=True)
    fqdnResolvedReverse = TruncatedCharField(null=True, max_length=255)
    ip = GenericIPAddressField(null=True)
    ipReverse = TruncatedCharField(db_index=True, null=True, max_length=255)
    ipReverseResolved = GenericIPAddressField(null=True)
    url = TruncatedCharField(null=True, max_length=4095)
    date = DateTimeField(auto_now=True, null=True, editable=True)


class UrlStatus(CerberusModel):
    """
        Fraudulent url status
    """

    STATUS = (("UP", "UP"), ("DOWN", "DOWN"), ("UNKNOWN", "UNKNOWN"))

    item = ForeignKey(ReportItem, null=False, related_name="urlStatus")
    directStatus = TruncatedCharField(
        max_length=10, null=False, choices=STATUS, default="UNKNOWN"
    )
    proxiedStatus = TruncatedCharField(
        max_length=10, null=True, choices=STATUS, default="UNKNOWN"
    )
    httpCode = IntegerField(null=True)
    score = IntegerField(null=True)
    isPhishing = BooleanField(null=False, default=False)
    date = DateTimeField(auto_now=True, null=False)
