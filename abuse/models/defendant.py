
from django.core.exceptions import ValidationError
from django.db.models import (BooleanField, DateTimeField, EmailField,
                              ForeignKey, ManyToManyField)

from .base import CerberusModel
from .helpers import TruncatedCharField


class DefendantCreationError(Exception):
    """
        Raise if there's multiple defendant with same customerId in DB
    """
    def __init__(self, message):
        super(DefendantCreationError, self).__init__(message)


class DefendantRevision(CerberusModel):
    """
        Effective detailed informations for a `abuse.models.Defendant`
    """
    email = EmailField(db_index=True, null=False, max_length=255)
    spareEmail = EmailField(null=True, max_length=255)
    firstname = TruncatedCharField(null=True, max_length=255)
    name = TruncatedCharField(null=True, max_length=255)
    city = TruncatedCharField(null=True, max_length=255)
    country = TruncatedCharField(null=True, max_length=32)
    billingCountry = TruncatedCharField(null=True, max_length=32)
    address = TruncatedCharField(null=True, max_length=1024)
    city = TruncatedCharField(null=True, max_length=255)
    zip = TruncatedCharField(null=True, max_length=255)
    phone = TruncatedCharField(null=True, max_length=255)
    lang = TruncatedCharField(null=True, max_length=32)
    legalForm = TruncatedCharField(null=True, max_length=255)
    organisation = TruncatedCharField(null=True, max_length=255)
    creationDate = DateTimeField(null=False)
    isVIP = BooleanField(null=False, default=False)
    isGS = BooleanField(null=False, default=False)
    isInternal = BooleanField(null=False, default=False)
    state = TruncatedCharField(null=True, max_length=255)


class Defendant(CerberusModel):
    """
        A person or entity (one of your customer) accused of something illegal
        by `abuse.models.Provider`
    """
    customerId = TruncatedCharField(db_index=True, null=False, max_length=255)
    details = ForeignKey(DefendantRevision, null=False)
    tags = ManyToManyField('Tag', null=True)

    @classmethod
    def get_or_create_defendant(cls, infos):
        """
            Create defendant or get it if exists
        """
        try:
            fields = DefendantRevision.get_fields()
            _infos = {k: v for k, v in infos.iteritems() if k in fields}
            customer_id = infos.get('customerId')
        except (AttributeError, KeyError, TypeError) as ex:
            raise DefendantCreationError(str(ex))

        try:
            created = False
            if DefendantRevision.filter(**_infos).count():
                revision = DefendantRevision.filter(**_infos).last()
            else:
                revision = DefendantRevision.create(**_infos)
                created = True
            defendants = Defendant.filter(customerId=customer_id)
            if len(defendants) > 1:
                raise DefendantCreationError(
                    'multiple defendants for customerId {}'.format(customer_id)
                )
            if len(defendants) == 1:
                defendant = defendants.first()
            else:
                defendant = cls.create(
                    customerId=customer_id, details=revision
                )
            if created:
                defendant.details = revision
                defendant.save()
                DefendantHistory.create(
                    defendant=defendant, revision=revision
                )
        except ValidationError as ex:
            raise ValidationError(str(ex))
        return defendant


class DefendantHistory(CerberusModel):
    """
        Log `abuse.models.Defendant`/`abuse.models.DefendantRevision`
        mapping changes
    """
    defendant = ForeignKey(Defendant, null=False)
    revision = ForeignKey(DefendantRevision, null=False)
    date = DateTimeField(auto_now=True)


class DefendantComment(CerberusModel):
    """
        Comment on a `abuse.models.Defendant`
    """
    defendant = ForeignKey(Defendant, null=False, related_name='comments')
    comment = ForeignKey('Comment', null=False)
