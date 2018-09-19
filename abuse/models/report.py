
from django.db.models import (
    DateTimeField,
    TextField,
    ForeignKey,
    ManyToManyField,
    PROTECT,
    SET_NULL,
)

from .base import CerberusModel
from .helpers import TruncatedCharField


class Report(CerberusModel):
    """
        Cerberus report model: basically an extraction of
        usefull relevant informations of an email report

        A report can be attached to a `abuse.models.Ticket`
    """

    REPORT_STATUS = (
        ("New", "New"),
        ("Archived", "Archived"),
        ("Attached", "Attached"),
        ("PhishToCheck", "PhishToCheck"),
        ("ToValidate", "ToValidate"),
    )

    REPORT_TREATED_MODE = (("NONE", "None"), ("MANU", "Manual"), ("AUTO", "Auto"))

    body = TextField(null=False)

    provider = ForeignKey(
        "Provider", null=False, related_name="provider", on_delete=PROTECT
    )

    defendant = ForeignKey(
        "Defendant", null=True, related_name="reportDefendant", on_delete=PROTECT
    )

    category = ForeignKey(
        "Category", null=True, related_name="reportCategory", on_delete=PROTECT
    )

    service = ForeignKey("Service", null=True)

    ticket = ForeignKey(
        "Ticket", null=True, related_name="reportTicket", on_delete=SET_NULL
    )

    receivedDate = DateTimeField(null=False)

    subject = TextField(null=True)

    status = TruncatedCharField(
        db_index=True, max_length=32, null=False, choices=REPORT_STATUS, default="New"
    )

    filename = TruncatedCharField(max_length=1023, null=False)

    tags = ManyToManyField("Tag", null=True)

    attachments = ManyToManyField("AttachedDocument", null=True)

    treatedMode = TruncatedCharField(
        max_length=4, null=False, choices=REPORT_TREATED_MODE, default="NONE"
    )

    def get_attached_ipaddr(self):
        """
            Returns all attached IP addresses
        """
        from ..utils.networking import get_ip_network

        items = (
            self.reportItemRelatedReport.all()
            .values_list("ip", "fqdnResolved")
            .distinct()
        )

        ips = [ip_addr for sub in items for ip_addr in sub if ip_addr]
        ips = [ip for ip in ips if get_ip_network(ip) == "managed"]
        return list(set(ips))

    def get_attached_urls(self):
        """
            Returns all attached URL
        """
        urls = self.reportItemRelatedReport.filter(itemType="URL").values_list(
            "rawItem", flat=True
        )

        return list(set(urls))

    def get_attached_fqdn(self):
        """
            Returns all attached FQDN
        """
        fqdn = self.reportItemRelatedReport.filter(itemType="FQDN").values_list(
            "rawItem", flat=True
        )

        return list(set(fqdn))

    def attach_url_matching_domain(self, domain):

        from .reportitem import ReportItem
        from ..utils import networking
        from ..parsers import ParsedEmail, Parser

        parser = Parser()
        parsed_email = ParsedEmail()

        template = parser.get_template("default")
        parser._apply_template(parsed_email, self.body, template)
        parsed_email.clean_items()

        for url in parsed_email.urls:
            if self.reportItemRelatedReport.filter(rawItem=url).exists():
                continue
            _domain = networking.get_url_hostname(url)
            if domain == _domain:
                item = {"itemType": "URL", "report_id": self.id, "rawItem": url[:4000]}
                item.update(networking.get_reverses_for_item(url, nature="URL"))
                ReportItem.create(**item)

    def add_tag(self, tag_name):
        """
            Add workflow tag to `abuse.models.Report`
        """
        from .tag import Tag
        from ..utils.text import string_to_underscore_case

        name = string_to_underscore_case(tag_name)

        self.tags.add(
            Tag.get_or_create(
                codename=name, name="report:{}".format(name), tagType="Report"
            )[0]
        )
