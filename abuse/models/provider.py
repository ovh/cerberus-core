
from django.db.models import (
    ForeignKey,
    BooleanField,
    ManyToManyField,
    ObjectDoesNotExist,
)

from .base import CerberusModel
from .helpers import TruncatedCharField


class Provider(CerberusModel):
    """
        A source of reports
    """

    PROVIDER_PRIORITY = (
        ("Low", "Low"),
        ("Normal", "Normal"),
        ("High", "High"),
        ("Critical", "Critical"),
    )
    email = TruncatedCharField(primary_key=True, max_length=255)
    name = TruncatedCharField(null=True, max_length=255)
    trusted = BooleanField(null=False, default=False)
    parseable = BooleanField(null=False, default=False)
    defaultCategory = ForeignKey("Category", null=True)
    apiKey = TruncatedCharField(null=True, max_length=255)
    priority = TruncatedCharField(
        max_length=32, null=False, choices=PROVIDER_PRIORITY, default="Normal"
    )
    tags = ManyToManyField("Tag", null=True)

    @classmethod
    def get_or_create_provider(cls, email):
        """
            Create provider or get it if existing
        """
        from ..parsers import Parser

        provider = cls.get_or_create(email=email)[0]

        # For providers using special email addresses
        # (e.g uniqueid-4942456@provider.com), these addresses are trusted
        # if the main *@provider is trusted too
        for reg, val in Parser.providers_generic.iteritems():
            if reg.match(provider.email):
                try:
                    prov = cls.get(email=val)
                    if prov.trusted:
                        provider.trusted = True
                    if prov.defaultCategory:
                        provider.defaultCategory = prov.defaultCategory
                    provider.save()
                    break
                except (KeyError, ObjectDoesNotExist):
                    break

        return provider
