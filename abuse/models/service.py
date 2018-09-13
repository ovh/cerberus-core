
from django.core.exceptions import MultipleObjectsReturned

from .base import CerberusModel
from .helpers import TruncatedCharField


class Service(CerberusModel):
    """
        `abuse.models.Defendant`'s service (product) description
    """
    name = TruncatedCharField(null=False, max_length=2048)
    domain = TruncatedCharField(null=True, max_length=2048)
    componentType = TruncatedCharField(null=True, max_length=256)
    componentSubType = TruncatedCharField(null=True, max_length=256)
    reference = TruncatedCharField(null=True, max_length=256)
    serviceId = TruncatedCharField(null=True, max_length=256)

    @classmethod
    def get_or_create_service(cls, service_infos):
        """
            Create service or get it if exists
        """
        valid_infos = {}
        for key, value in service_infos.iteritems():
            if key in cls.get_fields():
                valid_infos[key] = value
        try:
            service, _ = cls.get_or_create(**valid_infos)
        except MultipleObjectsReturned:
            service = cls.filter(name=valid_infos['name'])[0]
        return service
