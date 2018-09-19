
import operator
import random
import string

from datetime import datetime, timedelta

from django.db import IntegrityError
from django.db.models import (
    DateTimeField,
    ForeignKey,
    Q,
    ManyToManyField,
    PROTECT,
    BooleanField,
    IntegerField,
    ObjectDoesNotExist,
)
from django.contrib.auth.models import User

from .base import CerberusModel
from .helpers import TruncatedCharField
from ..tasks import cancel, enqueue, is_job_scheduled


class NoIpaddrItems(Exception):
    """
        raised when `abuse.models.Ticket` has no IP addresses attached
    """

    def __init__(self, message):
        super(NoIpaddrItems, self).__init__(message)


class MultipleIpaddrItems(Exception):
    """
        raised when `abuse.models.Ticket` has multiple IP addresses attached
    """

    def __init__(self, message):
        super(MultipleIpaddrItems, self).__init__(message)


class Ticket(CerberusModel):
    """
        Aggregation of `abuse.models.Report`
    """

    TICKET_STATUS = (
        ("ActionError", "ActionError"),
        ("Open", "Open"),
        ("Paused", "Paused"),
        ("Answered", "Answered"),
        ("Closed", "Closed"),
        ("Alarm", "Alarm"),
        ("WaitingAnswer", "WaitingAnswer"),
        ("Reopened", "Reopened"),
    )

    TICKET_PRIORITY = (
        ("Low", "Low"),
        ("Normal", "Normal"),
        ("High", "High"),
        ("Critical", "Critical"),
    )

    PRIORITY_LEVEL = {"Low": 3, "Normal": 2, "High": 1, "Critical": 0}  # Lower, higher

    publicId = TruncatedCharField(max_length=10, blank=True, null=True, unique=True)
    mailerId = IntegerField(null=True)
    defendant = ForeignKey(
        "Defendant", null=True, related_name="ticketDefendant", on_delete=PROTECT
    )
    category = ForeignKey(
        "Category", null=False, related_name="ticketCategory", on_delete=PROTECT
    )
    service = ForeignKey("Service", null=True)
    resolution = ForeignKey("Resolution", null=True)
    level = IntegerField(null=False, default=0)
    creationDate = DateTimeField(null=False)
    modificationDate = DateTimeField(auto_now=True, null=False)
    alarm = BooleanField(null=False, default=False)
    status = TruncatedCharField(
        db_index=True, max_length=32, null=False, choices=TICKET_STATUS, default="Open"
    )
    previousStatus = TruncatedCharField(
        max_length=32, null=False, choices=TICKET_STATUS, default="Open"
    )
    treatedBy = ForeignKey(
        User, null=True, related_name="ticketUser", on_delete=PROTECT
    )
    confidential = BooleanField(null=False, default=False)
    priority = TruncatedCharField(
        max_length=32, null=False, choices=TICKET_PRIORITY, default="Normal"
    )
    snoozeStart = DateTimeField(null=True)
    snoozeDuration = IntegerField(null=True)
    pauseStart = DateTimeField(null=True)
    pauseDuration = IntegerField(null=True)
    action = ForeignKey("ServiceAction", null=True, on_delete=PROTECT)
    moderation = BooleanField(null=False, default=False)
    protected = BooleanField(null=False, default=False)
    escalated = BooleanField(null=False, default=False)
    update = BooleanField(null=False, default=True)
    locked = BooleanField(null=False, default=False)
    tags = ManyToManyField("Tag", null=True)
    jobs = ManyToManyField("ServiceActionJob", null=True)
    attachments = ManyToManyField("AttachedDocument", null=True)

    @classmethod
    def search(cls, defendant, category, service):
        """
            Get ticket if exists
        """
        return cls.filter(
            ~(Q(status="Closed")),
            defendant=defendant,
            category=category,
            service=service,
            update=True,
        ).last()

    @classmethod
    def create_ticket(
        cls, defendant, category, service, priority="Normal", attach_new=True
    ):
        """
            Create a new ticket

            :param `abuse.models.Defendant` defendant: the defendant
            :param `abuse.models.Category` category: the category
            :param `abuse.models.Service` service: the service
            :param str priority: ticket`s priority
            :param bool attach_new: attach matching `abuse.models.Report`
            :rtype: `abuse.models.Ticket`
            :return: a Ticket instance
        """
        from .report import Report

        charset = string.ascii_uppercase.translate(None, "AEIOUY")

        ticket = None
        # While publicId is not valid
        while True:
            try:
                public_id = "".join(random.sample(charset, 10))
                ticket = cls.create(
                    publicId=public_id,
                    creationDate=datetime.now(),
                    defendant=defendant,
                    category=category,
                    service=service,
                    priority=priority,
                    update=True,
                )
                if all((defendant, service, category)) and attach_new:
                    Report.filter(
                        service=service,
                        defendant=defendant,
                        category=category,
                        ticket=None,
                        status="New",
                    ).update(ticket=ticket, status="Attached")
                break
            except (IntegrityError, ValueError):
                continue
        return ticket

    def set_higher_priority(self):
        """
            Set `abuse.models.Ticket` higher priority available through its
            `abuse.models.Provider`
        """
        from .defendant import Defendant

        priority = "Normal"

        priorities = list(
            set(self.reportTicket.all().values_list("provider__priority", flat=True))
        )

        ordered_priorities = sorted(
            self.PRIORITY_LEVEL.items(), key=operator.itemgetter(1)
        )

        for _priority, _ in ordered_priorities:
            if _priority in priorities:
                priority = _priority
                break

        if self.defendant:  # Warning for new customer or "big" ticket
            defendant = Defendant.get(customerId=self.defendant.customerId)
            if self.PRIORITY_LEVEL[priority] > self.PRIORITY_LEVEL["High"]:
                date_limit = datetime.now() - timedelta(days=30)
                if (
                    defendant.details.creationDate >= date_limit
                    or self.reportTicket.count() > 50
                ):
                    priority = "High"

        self.priority = priority
        self.save(update_fields=["priority"])

    def get_emailed_providers(self, email_only=True):

        from .provider import Provider

        if not self.mailerId:
            return set()

        provider_emails = (
            Provider.filter(provider__ticket=self)
            .values_list("email", flat=True)
            .distinct()
        )

        logs = list(
            set(
                self.ticketHistory.filter(actionType="SendEmail").values_list(
                    "action", flat=True
                )
            )
        )
        emailed = [l.split("to ")[1].lower() for l in logs]
        emailed = set([eml for eml in emailed if eml in provider_emails])

        if email_only:
            return emailed

        return Provider.filter(email__in=emailed)

    def get_reports_provider_email(self):

        from .provider import Provider

        return list(
            set(
                Provider.filter(provider__ticket=self)
                .values_list("email", flat=True)
                .distinct()
            )
        )

    def has_defendant_email_responses(self):

        if not self.mailerId:
            return False

        # XXX: TODO: directly add recipient category in log
        logs = list(
            set(
                self.ticketHistory.filter(actionType="ReceiveEmail").values_list(
                    "action", flat=True
                )
            )
        )
        senders = set([l.split("from ")[1].lower() for l in logs])

        from ..services import EmailService

        emails = EmailService.get_emails(self)

        for email in emails:
            if (
                email.category.lower() == "defendant"
                and email.sender.lower() in senders
            ):
                return True
        return False

    def has_defendant_email_requests(self):

        if not self.mailerId:
            return False

        # XXX: TODO: directly add recipient category in log
        logs = list(
            set(
                self.ticketHistory.filter(actionType="SendEmail").values_list(
                    "action", flat=True
                )
            )
        )
        recipients = set([l.split("to ")[1].lower() for l in logs])

        from ..services import EmailService

        emails = EmailService.get_emails(self)

        for email in emails:
            if (
                email.category.lower() == "defendant"
                and email.recipient.lower() in recipients
            ):
                return True
        return False

    def get_service_action_ipaddr(self):

        ips = []

        for report in self.reportTicket.all():
            ips.extend(report.get_attached_ipaddr())

        ips = list(set(ips))

        if not ips:
            raise NoIpaddrItems("ticket {} has no ipaddr items".format(self.id))
        if len(ips) > 1:
            raise MultipleIpaddrItems(
                "ticket {} has multiple ipaddr items".format(self.id)
            )

        return ips[0]

    def verify_service_action_ipaddr(self, ip_addr):

        ticket_items = (
            self.reportTicket.all()
            .values_list(
                "reportItemRelatedReport__ip", "reportItemRelatedReport__fqdnResolved"
            )
            .distinct()
        )

        ips = [ip for items in ticket_items for ip in items if ip]
        ips = list(set(ips))

        if ip_addr not in ips:
            raise ValueError("Specified IP address not attached to ticket")

    def cancel_pending_jobs(self, ip_addr=None, reason="answered"):

        query = Q()
        if ip_addr:
            query &= Q(ip=ip_addr)

        for job in self.jobs.filter(query):
            if is_job_scheduled(job.asynchronousJobId):
                cancel(job.asynchronousJobId)
                job.status = "cancelled by {}".format(reason)
                job.save()

    def get_action_remaining_time(self):

        if not all((self.snoozeStart, self.snoozeDuration)):
            return 0

        delay = self.snoozeStart + timedelta(seconds=self.snoozeDuration)
        return int((delay - datetime.now()).total_seconds())

    def add_tag(self, tag_name):

        from .tag import Tag

        self.tags.add(Tag.get(name=tag_name, tagType="Ticket"))

    def add_comment(self, comment, user=None):
        """
            Add a `abuse.models.Comment` to given `abuse.models.Ticket`

            :param `abuse.models.Ticket` ticket: a ticket instance
            :param str comment: the comment to add
            :param str user: the author
        """
        from .misc import Comment
        from .history import History

        if not user:
            user = "abuse.robot"

        try:
            author = User.objects.get(username=user)
        except (ValueError, TypeError, ObjectDoesNotExist):
            raise ValueError("invalid user {}".format(user))

        comment = Comment.create(user=author, comment=comment)

        TicketComment.create(ticket=self, comment=comment)
        History.log_ticket_action(ticket=self, action="add_comment", user=author)

    def pause(self, duration, user=None):
        """
            Pause ticket
        """
        try:
            _duration = int(duration)
            if _duration > 2592000:
                raise ValueError("Invalid pause duration {}".format(_duration))
        except (TypeError, ValueError):
            raise ValueError("Invalid pause duration {}".format(_duration))

        self.pauseStart = datetime.now()
        self.pauseDuration = _duration
        self.save(update_fields=["pauseStart", "pauseDuration"])
        self.set_status("Paused", user=user)

        # Delay jobs
        delay = timedelta(seconds=self.pauseDuration)
        enqueue("ticket.delay_jobs", ticket=self.id, delay=delay, back=False)

    def unpause(self, user=None):
        """
            Unpause ticket
        """
        # Delay jobs
        delay = timedelta(seconds=self.pauseDuration) - (
            datetime.now() - self.pauseStart
        )
        enqueue("ticket.delay_jobs", ticket=self.id, delay=delay, back=True)

        if (
            self.previousStatus == "WaitingAnswer"
            and self.snoozeDuration
            and self.snoozeStart
        ):
            self.snoozeDuration = (
                self.snoozeDuration + (datetime.now() - self.pauseStart).seconds
            )

        self.pauseStart = None
        self.pauseDuration = None
        self.save(update_fields=["pauseStart", "pauseDuration", "snoozeDuration"])
        self.set_status(self.previousStatus, user=user)

    def set_status(self, status, resolution_codename=None, user=None):
        """
            Update status and log action
        """
        if status not in [s[0] for s in self.TICKET_STATUS]:
            raise ValueError('invalid status "{}" for ticket'.format(status))

        from .history import History

        self.previousStatus = self.status
        self.status = status

        if status in ("Closed", "Alarm", "Answered", "ActionError"):
            self.snoozeStart = None
            self.snoozeDuration = None
            self.action = None

        self.save(
            update_fields=[
                "status",
                "previousStatus",
                "action",
                "snoozeStart",
                "snoozeDuration",
            ]
        )

        if status == "Closed":
            if self.mailerId:
                enqueue("ticket.close_emails_thread", ticket_id=self.id)
            self.reportTicket.all().update(status="Archived")
            enqueue("ticket.cancel_pending_jobs", ticket_id=self.id, status=status)
        else:
            self.reportTicket.all().update(status="Attached")

        History.log_ticket_action(
            ticket=self,
            action="change_status",
            user=user,
            previous_value=self.previousStatus,
            new_value=self.status,
            close_reason=resolution_codename,
        )


class TicketComment(CerberusModel):
    """
        Comment on a `abuse.models.Ticket`
    """

    ticket = ForeignKey(Ticket, null=False, related_name="comments")
    comment = ForeignKey("Comment", null=False)
