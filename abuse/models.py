# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016, OVH SAS
#
# This file is part of Cerberus-core.
#
# Cerberus-core is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""
    Cerberus model

"""

from django.db import models
from django.contrib.auth.models import User
from jsonfield import JSONField


# http://stackoverflow.com/questions/1809531/truncating-unicode-so-it-fits-a-maximum-size-when-encoded-for-wire-transfer
def unicode_truncate(s, length, encoding='utf-8'):
    encoded = s.encode(encoding)[:length]
    return encoded.decode(encoding, 'ignore')


# http://stackoverflow.com/questions/3459843/auto-truncating-fields-at-max-length-in-django-charfields
class TruncatedCharField(models.CharField):
    def get_prep_value(self, value):
        value = super(TruncatedCharField, self).get_prep_value(value)
        if value:
            return unicode_truncate(value, self.max_length)
        return value


class ServiceAction(models.Model):
    """
        An action on a customer's service (suspend, shutdown, breach of contract)

        Required by `adapters.services.action.abstract.ActionServiceBase`
    """
    name = TruncatedCharField(null=False, max_length=1024)
    module = TruncatedCharField(null=False, max_length=32)
    level = TruncatedCharField(null=False, max_length=8)


class ServiceActionJob(models.Model):
    """
        Because execution of an ServiceAction is asynchronous, keeping exc info of it
    """
    action = models.ForeignKey(ServiceAction, null=False)
    asynchronousJobId = TruncatedCharField(null=True, max_length=128)
    actionTodoId = models.IntegerField(null=True)
    status = TruncatedCharField(null=False, max_length=32, default='pending')
    comment = TruncatedCharField(null=True, max_length=256)
    creationDate = models.DateTimeField(null=False)
    executionDate = models.DateTimeField(null=True)
    ip = models.IPAddressField(null=True)


class Category(models.Model):
    """
        The category of a ticket/report
    """
    name = TruncatedCharField(primary_key=True, max_length=32)
    label = TruncatedCharField(unique=True, null=False, blank=True, max_length=255)
    description = TruncatedCharField(null=False, blank=True, max_length=255)


class ApiRoute(models.Model):
    """
        List all available API routes
    """
    HTTP_METHOD = (
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('PATCH', 'PATCH'),
        ('DELETE', 'DELETE'),
    )
    method = TruncatedCharField(max_length=32, null=False, choices=HTTP_METHOD)
    endpoint = TruncatedCharField(null=False, max_length=512)


class Role(models.Model):
    """
        A `abuse.models.Role` defines a set of allowed `abuse.models.ApiRoute`
    """
    codename = TruncatedCharField(null=False, max_length=256)
    name = TruncatedCharField(null=False, max_length=256)
    allowedRoutes = models.ManyToManyField(ApiRoute, db_column='endpoints')
    modelsAuthorizations = JSONField()


class Operator(models.Model):
    """
        Cerberus `abuse.models.User` + `abuse.models.Role` = `abuse.models.Operator`
    """
    user = models.OneToOneField(User, null=False)
    role = models.ForeignKey(Role, null=False)


class Tag(models.Model):
    """
        A way to filter / add extra infos to Cerberus main classes :

        - `abuse.models.Defendant`
        - `abuse.models.Ticket`
        - `abuse.models.Report`
        - `abuse.models.Provider`
        - `abuse.models.News`
    """
    TAG_TYPE = (
        ('Defendant', 'Defendant'),
        ('Ticket', 'Ticket'),
        ('Report', 'Report'),
        ('Provider', 'Provider'),
        ('News', 'News'),
    )
    codename = TruncatedCharField(null=False, max_length=256, editable=False)
    name = TruncatedCharField(null=False, max_length=255)
    tagType = TruncatedCharField(max_length=32, null=False, choices=TAG_TYPE)
    level = models.SmallIntegerField(null=False, default=0)


class EmailFilter(models.Model):
    """
        Specify filters for incoming emails
    """
    FILTER_SCOPE = (
        ('Provider', 'Provider'),
        ('Recipients', 'Recipients'),
        ('Subject', 'Subject'),
        ('Body', 'Body'),
    )
    scope = TruncatedCharField(max_length=32, null=False, choices=FILTER_SCOPE)
    value = TruncatedCharField(max_length=1024, null=False)


class EmailFilterTag(models.Model):
    """
        `abuse.models.EmailFilter` / `abuse.models.Tag` association
    """
    name = TruncatedCharField(max_length=1024, null=False)
    filters = models.ManyToManyField(EmailFilter, null=False)
    tags = models.ManyToManyField(Tag, null=False)


class DefendantRevision(models.Model):
    """
        Effective detailed informations for a `abuse.models.Defendant`
    """
    email = models.EmailField(db_index=True, null=False, max_length=255)
    spareEmail = models.EmailField(null=True, max_length=255)
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
    creationDate = models.DateTimeField(null=False)
    isVIP = models.BooleanField(null=False, default=False)
    isGS = models.BooleanField(null=False, default=False)
    isInternal = models.BooleanField(null=False, default=False)
    state = TruncatedCharField(null=True, max_length=255)


class Defendant(models.Model):
    """
        A person or entity (one of your customer) accused of something illegal
        by a `abuse.models.Plaintiff` or a `abuse.models.Provider`
    """
    customerId = TruncatedCharField(db_index=True, null=False, max_length=255)
    details = models.ForeignKey(DefendantRevision, null=False)
    tags = models.ManyToManyField(Tag, null=True)


class DefendantHistory(models.Model):
    """
        Keep history of `abuse.models.Defendant`/`abuse.models.DefendantRevision` mapping
    """
    defendant = models.ForeignKey(Defendant, null=False)
    revision = models.ForeignKey(DefendantRevision, null=False)
    date = models.DateTimeField(auto_now=True)


class Plaintiff(models.Model):
    """
        A plaintiff is a person or entity who initiates an action against a `abuse.models.Defendant`
    """
    PLAINTIFF_TYPE = (
        ('EXT', 'External'),
        ('INH', 'Internal Human'),
        ('INB', 'Internal Bot'),
    )

    email = models.EmailField(null=True, max_length=255)
    name = TruncatedCharField(null=True, max_length=255)
    company = TruncatedCharField(null=True, max_length=255)
    ip = models.IPAddressField(null=True)
    plaintiffType = TruncatedCharField(max_length=3, null=False, choices=PLAINTIFF_TYPE, default='EXT')


class Service(models.Model):
    """
        `abuse.models.Defendant`'s service (product) description
    """
    name = TruncatedCharField(null=False, max_length=2048)
    domain = TruncatedCharField(null=True, max_length=2048)
    componentType = TruncatedCharField(null=True, max_length=256)
    componentSubType = TruncatedCharField(null=True, max_length=256)
    reference = TruncatedCharField(null=True, max_length=256)
    serviceId = TruncatedCharField(null=True, max_length=256)


class Resolution(models.Model):
    """
        Ticket resolution
    """
    codename = TruncatedCharField(null=False, max_length=1024)


class AttachedDocument(models.Model):
    """
        Attached document for a `abuse.models.Report`
    """
    name = TruncatedCharField(null=True, max_length=255)
    filename = TruncatedCharField(null=False, max_length=1023)
    filetype = TruncatedCharField(null=False, max_length=1023)


class Ticket(models.Model):
    """
        Cerberus ticket model: it brings `abuse.models.Report` together based
        on the tuple (`abuse.models.Defendant`, `abuse.models.Service`, `abuse.models.Category`)

        A Ticket is created manually or automatically if a report's provider is 'trusted'.
    """
    TICKET_STATUS = (
        ('ActionError', 'ActionError'),
        ('Open', 'Open'),
        ('Paused', 'Paused'),
        ('Answered', 'Answered'),
        ('Closed', 'Closed'),
        ('Alarm', 'Alarm'),
        ('WaitingAnswer', 'WaitingAnswer'),
        ('Reopened', 'Reopened'),
    )

    TICKET_PRIORITY = (
        ('Low', 'Low'),
        ('Normal', 'Normal'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    )

    publicId = TruncatedCharField(max_length=10, blank=True, null=True, unique=True)
    mailerId = models.IntegerField(null=True)
    defendant = models.ForeignKey(Defendant, null=True, related_name='ticketDefendant', on_delete=models.PROTECT)
    category = models.ForeignKey(Category, null=False, related_name='ticketCategory', on_delete=models.PROTECT)
    service = models.ForeignKey(Service, null=True)
    resolution = models.ForeignKey(Resolution, null=True)
    level = models.IntegerField(null=False, default=0)
    creationDate = models.DateTimeField(null=False)
    modificationDate = models.DateTimeField(auto_now=True, null=False)
    alarm = models.BooleanField(null=False, default=False)
    status = TruncatedCharField(db_index=True, max_length=32, null=False, choices=TICKET_STATUS, default='Open')
    previousStatus = TruncatedCharField(max_length=32, null=False, choices=TICKET_STATUS, default='Open')
    treatedBy = models.ForeignKey(User, null=True, related_name='ticketUser', on_delete=models.PROTECT)
    confidential = models.BooleanField(null=False, default=False)
    priority = TruncatedCharField(max_length=32, null=False, choices=TICKET_PRIORITY, default='Normal')
    snoozeStart = models.DateTimeField(null=True)
    snoozeDuration = models.IntegerField(null=True)
    pauseStart = models.DateTimeField(null=True)
    pauseDuration = models.IntegerField(null=True)
    action = models.ForeignKey(ServiceAction, null=True, on_delete=models.PROTECT)
    moderation = models.BooleanField(null=False, default=False)
    protected = models.BooleanField(null=False, default=False)
    escalated = models.BooleanField(null=False, default=False)
    update = models.BooleanField(null=False, default=True)
    locked = models.BooleanField(null=False, default=False)
    tags = models.ManyToManyField(Tag, null=True)
    jobs = models.ManyToManyField(ServiceActionJob, null=True)
    attachments = models.ManyToManyField(AttachedDocument, null=True)


class Provider(models.Model):
    """
        A source of reports
    """
    PROVIDER_PRIORITY = (
        ('Low', 'Low'),
        ('Normal', 'Normal'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    )
    email = TruncatedCharField(primary_key=True, max_length=255)
    name = TruncatedCharField(null=True, max_length=255)
    trusted = models.BooleanField(null=False, default=False)
    parseable = models.BooleanField(null=False, default=False)
    defaultCategory = models.ForeignKey(Category, null=True)
    apiKey = TruncatedCharField(null=True, max_length=255)
    priority = TruncatedCharField(max_length=32, null=False, choices=PROVIDER_PRIORITY, default='Normal')
    tags = models.ManyToManyField(Tag, null=True)


class Report(models.Model):
    """
        Cerberus report model: basically an extraction of usefull relevant informations of an email

        A report can be attached to a `abuse.models.Ticket`
    """
    REPORT_STATUS = (
        ('New', 'New'),
        ('Archived', 'Archived'),
        ('Attached', 'Attached'),
        ('PhishToCheck', 'PhishToCheck'),
        ('ToValidate', 'ToValidate'),
    )

    REPORT_TREATED_MODE = (
        ('NONE', 'None'),
        ('MANU', 'Manual'),
        ('AUTO', 'Auto'),
    )

    body = models.TextField(null=False)
    provider = models.ForeignKey(Provider, null=False, related_name='provider', on_delete=models.PROTECT)
    plaintiff = models.ForeignKey(Plaintiff, null=True, related_name='plaintiff', on_delete=models.SET_NULL)
    defendant = models.ForeignKey(Defendant, null=True, related_name='reportDefendant', on_delete=models.PROTECT)
    category = models.ForeignKey(Category, null=True, related_name='reportCategory', on_delete=models.PROTECT)
    service = models.ForeignKey(Service, null=True)
    ticket = models.ForeignKey(Ticket, null=True, related_name='reportTicket', on_delete=models.SET_NULL)
    receivedDate = models.DateTimeField(null=False)
    subject = models.TextField(null=True)
    treatedMode = TruncatedCharField(max_length=4, null=False, choices=REPORT_TREATED_MODE, default='NONE')
    status = TruncatedCharField(db_index=True, max_length=32, null=False, choices=REPORT_STATUS, default='New')
    filename = TruncatedCharField(max_length=1023, null=False)
    tags = models.ManyToManyField(Tag, null=True)
    attachments = models.ManyToManyField(AttachedDocument, null=True)


class ReportItem(models.Model):
    """
        Fraudulent item found in a `abuse.models.Repor`
    """
    ITEM_TYPE = (
        ('IP', 'Ip'),
        ('FQDN', 'Fqdn'),
        ('URL', 'Url'),
    )

    report = models.ForeignKey(Report, null=False, related_name='reportItemRelatedReport')
    rawItem = TruncatedCharField(db_index=True, max_length=4095)
    itemType = TruncatedCharField(max_length=4, null=True, choices=ITEM_TYPE)
    fqdn = TruncatedCharField(null=True, max_length=255)
    fqdnResolved = models.IPAddressField(db_index=True, null=True)
    fqdnResolvedReverse = TruncatedCharField(null=True, max_length=255)
    ip = models.IPAddressField(null=True)
    ipReverse = TruncatedCharField(db_index=True, null=True, max_length=255)
    ipReverseResolved = models.IPAddressField(null=True)
    url = TruncatedCharField(null=True, max_length=4095)
    date = models.DateTimeField(auto_now=True, null=True, editable=True)


class History(models.Model):
    """
        Ticket change history
    """
    ACTION_TYPE = (
        ('AddTag', 'AddTag'),
        ('RemoveTag', 'RemoveTag'),
        ('AddItem', 'AddItem'),
        ('UpdateItem', 'UpdateItem'),
        ('DeleteItem', 'DeleteItem'),
        ('AddProof', 'AddProof'),
        ('UpdateProof', 'UpdateProof'),
        ('DeleteProof', 'DeleteProof'),
        ('AddComment', 'AddComment'),
        ('UpdateComment', 'UpdateComment'),
        ('DeleteComment', 'DeleteComment'),
        ('ValidatePhishtocheck', 'ValidatePhishtocheck'),
        ('DenyPhishtocheck', 'DenyPhishtocheck'),
        ('ChangeStatus', 'ChangeStatus'),
        ('ChangeTreatedby', 'ChangeTreatedby'),
        ('SendEmail', 'SendEmail'),
        ('ReceiveEmail', 'ReceiveEmail'),
        ('AttachReport', 'AttachReport'),
        ('SetAction', 'SetAction'),
        ('CancelAction', 'CancelAction'),
        ('UpdateProperty', 'UpdateProperty'),
        ('CreateThreshold', 'CreateThreshold'),
        ('CreateMasscontact', 'CreateMasscontact'),
    )

    ticket = models.ForeignKey(Ticket, null=False, related_name='ticketHistory')
    user = models.ForeignKey(User, null=False)
    action = TruncatedCharField(null=False, max_length=255)
    actionType = TruncatedCharField(max_length=32, null=True, choices=ACTION_TYPE, default='UpdateProperty')
    ticketStatus = TruncatedCharField(null=True, max_length=32)
    date = models.DateTimeField(auto_now=True, null=False)


class Comment(models.Model):
    """
        Generic comment model
    """
    user = models.ForeignKey(User, null=False)
    comment = TruncatedCharField(null=False, max_length=65535)
    date = models.DateTimeField(auto_now=True, null=False)


class TicketComment(models.Model):
    """
        Comment on a `abuse.models.Ticket`
    """
    ticket = models.ForeignKey(Ticket, null=False, related_name='comments')
    comment = models.ForeignKey(Comment, null=False)


class DefendantComment(models.Model):
    """
        Comment on a `abuse.models.Defendant`
    """
    defendant = models.ForeignKey(Defendant, null=False, related_name='comments')
    comment = models.ForeignKey(Comment, null=False)


class Profile(models.Model):
    """
        Cerberus operator profile
    """
    name = TruncatedCharField(null=False, max_length=255)
    actions = models.ManyToManyField(ServiceAction, null=True)


class AbusePermission(models.Model):
    """
        Permission for an abuse user
    """
    user = models.ForeignKey(User, null=False)
    category = models.ForeignKey(Category, null=False)
    profile = models.ForeignKey(Profile, null=True)


class News(models.Model):
    """
        Cerberus news model
    """
    author = models.ForeignKey(User, null=False)
    title = TruncatedCharField(null=False, max_length=1023)
    content = TruncatedCharField(null=False, max_length=65535)
    tags = models.ManyToManyField('Tag', null=True)
    date = models.DateTimeField(auto_now=True, null=False)


class MailTemplate(models.Model):
    """
        Cerebrus `abuse.models.Ticket` emails are based on template
    """
    TEMPLATE_LANG = (
        ('FR', 'FR'),
        ('EN', 'EN'),
        ('CA', 'CA'),
    )

    RECIPIENT_TYPE = (
        ('Defendant', 'Defendant'),
        ('Plaintiff', 'Plaintiff'),
        ('Other', 'Other'),
        ('MassContact', 'MassContact'),
    )

    codename = TruncatedCharField(max_length=32)
    name = TruncatedCharField(null=False, max_length=255)
    lang = TruncatedCharField(max_length=2, null=False, choices=TEMPLATE_LANG, default='EN')
    subject = TruncatedCharField(null=False, max_length=1023)
    body = models.TextField(null=False)
    recipientType = TruncatedCharField(max_length=32, null=False, choices=RECIPIENT_TYPE, default='Defendant')


class Proof(models.Model):
    """
       Proof are elements validating the infrigment
    """
    ticket = models.ForeignKey(Ticket, null=False, related_name='proof')
    content = models.TextField(null=False)


class UrlStatus(models.Model):
    """
        Fraudulent url status
    """
    STATUS = (
        ('UP', 'UP'),
        ('DOWN', 'DOWN'),
        ('UNKNOWN', 'UNKNOWN'),
    )

    item = models.ForeignKey(ReportItem, null=False, related_name='urlStatus')
    directStatus = TruncatedCharField(max_length=10, null=False, choices=STATUS, default='UNKNOWN')
    proxiedStatus = TruncatedCharField(max_length=10, null=True, choices=STATUS, default='UNKNOWN')
    httpCode = models.IntegerField(null=True)
    score = models.IntegerField(null=True)
    isPhishing = models.BooleanField(null=False, default=False)
    date = models.DateTimeField(auto_now=True, null=False)


class TicketActionParams(models.Model):
    """
        Params for `abuse.models.TicketAction`
    """
    codename = TruncatedCharField(null=False, max_length=1024)
    value = models.IntegerField(null=False)


class TicketAction(models.Model):
    """
        List possible action on a `abuse.models.Ticket`

        Usefull for Cerberus UX "interact" modal
    """
    codename = TruncatedCharField(null=False, max_length=1024)


class TicketWorkflowPresetConfig(models.Model):
    """
        `abuse.models.TicketAction` / `abuse.models.TicketActionParams` association
    """
    action = models.ForeignKey(TicketAction, null=False)
    params = models.ManyToManyField(TicketActionParams, null=True)


class TicketWorkflowPreset(models.Model):
    """
        Preset for Cerberus UX "interact" modal
    """
    codename = TruncatedCharField(null=False, max_length=256)
    name = TruncatedCharField(max_length=256)
    templates = models.ManyToManyField(MailTemplate, null=True)
    config = models.ForeignKey(TicketWorkflowPresetConfig, null=True)
    groupId = models.PositiveSmallIntegerField(null=True)
    orderId = models.PositiveSmallIntegerField(null=True)
    roles = models.ManyToManyField(Role)


class ItemScreenshotFeedback(models.Model):
    """
        Check if `abuse.models.Defendant` views or not the screenshot of a Phishing item
    """
    item = models.ForeignKey(ReportItem, null=False, related_name='feedback')
    token = TruncatedCharField(null=False, max_length=256)
    isViewed = models.BooleanField(null=False, default=False)


class ContactedProvider(models.Model):
    """
        This model is usefull to save which provider have been contacted
        for a `abuse.models.Ticket`
    """
    ticket = models.ForeignKey(Ticket, null=False, related_name='contactedProviders')
    provider = models.ForeignKey(Provider, null=False)
    date = models.DateTimeField(auto_now=True, null=False)


class ReportThreshold(models.Model):
    """
        Automatically creates ticket if there are more than
        `threshold` new reports created during `interval` (days) for same (category/defendant/service)
    """
    category = models.ForeignKey(Category, null=False)
    threshold = models.IntegerField(null=False)
    interval = models.IntegerField(null=False)


class MassContact(models.Model):
    """
        Store details of different "mass contact" campaign.
    """
    campaignName = TruncatedCharField(max_length=256, null=False)
    category = models.ForeignKey(Category, null=False)
    user = models.ForeignKey(User, null=False)
    ipsCount = models.IntegerField(null=False)
    date = models.DateTimeField(auto_now=True, null=False)


class MassContactResult(models.Model):
    """
        Store result of a "mass contact" campaign.
    """
    MASSCONTACT_STATE = (
        ('Done', 'Done'),
        ('Pending', 'Pending'),
    )

    campaign = models.ForeignKey(MassContact, null=False)
    state = TruncatedCharField(max_length=32, null=False, choices=MASSCONTACT_STATE, default='Pending')
    matchingCount = models.IntegerField(null=False, default=0)  # Defendant found, report created
    notMatchingCount = models.IntegerField(null=False, default=0)  # No defendant found
    failedCount = models.IntegerField(null=False, default=0)  # Rq job failed


class StarredTicket(models.Model):
    """
        Association of `abuse.models.User` and `abuse.models.Ticket`
    """
    user = models.ForeignKey(User, null=False, related_name='starredTickets')
    ticket = models.ForeignKey(Ticket, null=False, related_name='starredBy')

    class Meta:
        unique_together = ("ticket", "user")
