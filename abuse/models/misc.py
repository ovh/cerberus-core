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
    Misc Cerberus model
"""

from django.db.models import (
    DateTimeField,
    TextField,
    ForeignKey,
    ManyToManyField,
    IntegerField,
    GenericIPAddressField,
    BooleanField,
    OneToOneField,
    PositiveSmallIntegerField,
)
from django.contrib.auth.models import User
from jsonfield import JSONField

from .base import CerberusModel
from .helpers import TruncatedCharField


class ServiceAction(CerberusModel):
    """
        An action on a customer's service (suspend, shutdown ...)
    """

    name = TruncatedCharField(null=False, max_length=1024)
    module = TruncatedCharField(null=False, max_length=32)
    level = TruncatedCharField(null=False, max_length=8)


class ServiceActionJob(CerberusModel):
    """
        `abuse.models.ServiceAction` execution state
    """

    action = ForeignKey(ServiceAction, null=False)
    asynchronousJobId = TruncatedCharField(null=True, max_length=128)
    actionTodoId = IntegerField(null=True)
    status = TruncatedCharField(null=False, max_length=32, default="pending")
    comment = TruncatedCharField(null=True, max_length=256)
    creationDate = DateTimeField(null=False)
    executionDate = DateTimeField(null=True)
    ip = GenericIPAddressField(null=True)


class Category(CerberusModel):
    """
        The category of a ticket/report
    """

    name = TruncatedCharField(primary_key=True, max_length=32)
    label = TruncatedCharField(unique=True, null=False, blank=True, max_length=255)
    description = TruncatedCharField(null=False, blank=True, max_length=255)


class ApiRoute(CerberusModel):
    """
        List all available API routes
    """

    HTTP_METHOD = (
        ("GET", "GET"),
        ("POST", "POST"),
        ("PUT", "PUT"),
        ("PATCH", "PATCH"),
        ("DELETE", "DELETE"),
    )
    method = TruncatedCharField(max_length=32, null=False, choices=HTTP_METHOD)
    endpoint = TruncatedCharField(null=False, max_length=512)


class Role(CerberusModel):
    """
        A `abuse.models.Role` defines a set
        of allowed `abuse.models.ApiRoute`
    """

    codename = TruncatedCharField(null=False, max_length=256)
    name = TruncatedCharField(null=False, max_length=256)
    allowedRoutes = ManyToManyField(ApiRoute, db_column="endpoints")
    modelsAuthorizations = JSONField()


class Operator(CerberusModel):
    """
        Cerberus `abuse.models.User` + `abuse.models.Role`
        = `abuse.models.Operator`
    """

    user = OneToOneField(User, null=False)
    role = ForeignKey(Role, null=False)


class EmailFilter(CerberusModel):
    """
        Specify filters for incoming emails
    """

    FILTER_SCOPE = (
        ("Provider", "Provider"),
        ("Recipients", "Recipients"),
        ("Subject", "Subject"),
        ("Body", "Body"),
    )
    scope = TruncatedCharField(max_length=32, null=False, choices=FILTER_SCOPE)
    value = TruncatedCharField(max_length=1024, null=False)


class EmailFilterTag(CerberusModel):
    """
        `abuse.models.EmailFilter` / `abuse.models.Tag` association
    """

    name = TruncatedCharField(max_length=1024, null=False)
    filters = ManyToManyField(EmailFilter, null=False)
    tags = ManyToManyField("Tag", null=False)

    @classmethod
    def get_tags_for_email(cls, provider, recipients, subject, body):
        """
            Return a list of tags based on email attributes
        """
        tags = []
        if not all((provider, subject, body)):
            return tags

        data = {
            "provider": provider.email,
            "recipients": " ".join(recipients).lower() if recipients else "",
            "subject": subject.lower(),
            "body": body.lower(),
        }

        for eft in cls.all():
            add = True
            for filtr in eft.filters.all():
                if filtr.value.lower() not in data[filtr.scope]:
                    add = False
                    break
            if add:
                tags.append(eft.tags.all())

        tags.append(provider.tags.all())
        tags = [i for sub in tags for i in sub]
        tags = list(set(tags))
        return tags


class Resolution(CerberusModel):
    """
        Ticket resolution
    """

    codename = TruncatedCharField(null=False, max_length=1024)


class AttachedDocument(CerberusModel):
    """
        Attached document for a `abuse.models.Report`
    """

    name = TruncatedCharField(null=True, max_length=255)
    filename = TruncatedCharField(null=False, max_length=1023)
    filetype = TruncatedCharField(null=False, max_length=1023)


class Comment(CerberusModel):
    """
        Generic comment model
    """

    user = ForeignKey(User, null=False)
    comment = TruncatedCharField(null=False, max_length=65535)
    date = DateTimeField(auto_now=True, null=False)


class Profile(CerberusModel):
    """
        Cerberus operator profile
    """

    name = TruncatedCharField(null=False, max_length=255)
    actions = ManyToManyField("ServiceAction", null=True)


class AbusePermission(CerberusModel):
    """
        Permission for an Cerberus user
    """

    user = ForeignKey(User, null=False)
    category = ForeignKey(Category, null=False)
    profile = ForeignKey(Profile, null=True)


class News(CerberusModel):
    """
        Cerberus news model
    """

    author = ForeignKey(User, null=False)
    title = TruncatedCharField(null=False, max_length=1023)
    content = TruncatedCharField(null=False, max_length=65535)
    tags = ManyToManyField("Tag", null=True)
    date = DateTimeField(auto_now=True, null=False)


class MailTemplate(CerberusModel):
    """
        Cerebrus `abuse.models.Ticket` emails are based on template
    """

    TEMPLATE_LANG = (("FR", "FR"), ("EN", "EN"), ("CA", "CA"))

    RECIPIENT_TYPE = (
        ("Defendant", "Defendant"),
        ("Plaintiff", "Plaintiff"),
        ("Other", "Other"),
        ("MassContact", "MassContact"),
    )

    codename = TruncatedCharField(max_length=32)
    name = TruncatedCharField(null=False, max_length=255)
    lang = TruncatedCharField(
        max_length=2, null=False, choices=TEMPLATE_LANG, default="EN"
    )
    subject = TruncatedCharField(null=False, max_length=1023)
    body = TextField(null=False)
    recipientType = TruncatedCharField(
        max_length=32, null=False, choices=RECIPIENT_TYPE, default="Defendant"
    )


class Proof(CerberusModel):
    """
       Proof are elements validating the infrigment
    """

    ticket = ForeignKey("Ticket", null=False, related_name="proof")
    content = TextField(null=False)


class TicketActionParams(CerberusModel):
    """
        Params for `abuse.models.TicketAction`
    """

    codename = TruncatedCharField(null=False, max_length=1024)
    value = IntegerField(null=False)


class TicketAction(CerberusModel):
    """
        List possible action on a `abuse.models.Ticket`

        Usefull for Cerberus UX "interact" modal
    """

    codename = TruncatedCharField(null=False, max_length=1024)


class TicketWorkflowPresetConfig(CerberusModel):
    """
        `abuse.models.TicketAction`/`abuse.models.TicketActionParams`
        association
    """

    action = ForeignKey(TicketAction, null=False)
    params = ManyToManyField(TicketActionParams, null=True)


class TicketWorkflowPreset(CerberusModel):
    """
        Preset for Cerberus UX "interact" modal
    """

    codename = TruncatedCharField(null=False, max_length=256)
    name = TruncatedCharField(max_length=256)
    templates = ManyToManyField(MailTemplate, null=True)
    config = ForeignKey(TicketWorkflowPresetConfig, null=True)
    groupId = PositiveSmallIntegerField(null=True)
    orderId = PositiveSmallIntegerField(null=True)
    roles = ManyToManyField(Role)


class ItemScreenshotFeedback(CerberusModel):
    """
        Check if `abuse.models.Defendant` views or not
        the screenshot of a Phishing item
    """

    item = ForeignKey("ReportItem", null=False, related_name="feedback")
    token = TruncatedCharField(null=False, max_length=256)
    isViewed = BooleanField(null=False, default=False)


class ReportThreshold(CerberusModel):
    """
        Automatically creates ticket if there are more than
        `threshold` new reports created during `interval` (days)
        for same (category/defendant/service)
    """

    category = ForeignKey(Category, null=False)
    threshold = IntegerField(null=False)
    interval = IntegerField(null=False)


class MassContact(CerberusModel):
    """
        Store details of different "mass contact" campaign.
    """

    campaignName = TruncatedCharField(max_length=256, null=False)
    category = ForeignKey(Category, null=False)
    user = ForeignKey(User, null=False)
    ipsCount = IntegerField(null=False)
    date = DateTimeField(auto_now=True, null=False)


class MassContactResult(CerberusModel):
    """
        Store result of a "mass contact" campaign.
    """

    MASSCONTACT_STATE = (("Done", "Done"), ("Pending", "Pending"))

    campaign = ForeignKey(MassContact, null=False)
    state = TruncatedCharField(
        max_length=32, null=False, choices=MASSCONTACT_STATE, default="Pending"
    )
    # Defendant found, report created
    matchingCount = IntegerField(null=False, default=0)
    # No defendant found
    notMatchingCount = IntegerField(null=False, default=0)
    # job failed
    failedCount = IntegerField(null=False, default=0)


class StarredTicket(CerberusModel):
    """
        Association of `abuse.models.User` and `abuse.models.Ticket`
    """

    user = ForeignKey(User, null=False, related_name="starredTickets")
    ticket = ForeignKey("Ticket", null=False, related_name="starredBy")

    class Meta:
        unique_together = ("ticket", "user")


class BusinessRules(CerberusModel):
    """
        Defines automation on a `abuse.models.Report`
    """

    RULES_TYPE = (
        ("Report", "Report"),
        ("EmailReply", "EmailReply"),
        ("CDNRequest", "CDNRequest"),
    )

    name = TruncatedCharField(max_length=256, null=False)
    orderId = PositiveSmallIntegerField(null=False)
    rulesType = TruncatedCharField(max_length=32, null=False, choices=RULES_TYPE)
    config = JSONField()


class BusinessRulesHistory(CerberusModel):
    """
        `abuse.models.BusinessRules` execution history
    """

    businessRules = ForeignKey(BusinessRules, null=False)
    defendant = ForeignKey("Defendant", null=True)
    service = ForeignKey("Service", null=True)
    report = ForeignKey("Report", null=True)
    ticket = ForeignKey("Ticket", null=True)
    date = DateTimeField(auto_now=True)
