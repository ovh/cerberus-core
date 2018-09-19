
import re

from datetime import datetime

from django.db.models import DateTimeField, ForeignKey
from django.contrib.auth.models import User

from .base import CerberusModel
from .helpers import TruncatedCharField


GENERIC_LOG_ACTION = (
    "add_item",
    "update_item",
    "delete_item",
    "add_proof",
    "update_proof",
    "delete_proof",
    "add_comment",
    "update_comment",
    "delete_comment",
)


class InvalidTicketHistoryAction(Exception):
    """
        Raise if the specified log action if not valid
    """

    def __init__(self, message):
        super(InvalidTicketHistoryAction, self).__init__(message)


class History(CerberusModel):
    """
        Ticket change history
    """

    ACTION_TYPE = (
        ("AddTag", "AddTag"),
        ("RemoveTag", "RemoveTag"),
        ("AddItem", "AddItem"),
        ("UpdateItem", "UpdateItem"),
        ("DeleteItem", "DeleteItem"),
        ("AddProof", "AddProof"),
        ("UpdateProof", "UpdateProof"),
        ("DeleteProof", "DeleteProof"),
        ("AddComment", "AddComment"),
        ("UpdateComment", "UpdateComment"),
        ("DeleteComment", "DeleteComment"),
        ("ValidatePhishtocheck", "ValidatePhishtocheck"),
        ("DenyPhishtocheck", "DenyPhishtocheck"),
        ("ChangeStatus", "ChangeStatus"),
        ("ChangeTreatedby", "ChangeTreatedby"),
        ("SendEmail", "SendEmail"),
        ("ReceiveEmail", "ReceiveEmail"),
        ("AttachReport", "AttachReport"),
        ("SetAction", "SetAction"),
        ("CancelAction", "CancelAction"),
        ("UpdateProperty", "UpdateProperty"),
        ("CreateThreshold", "CreateThreshold"),
        ("CreateMasscontact", "CreateMasscontact"),
    )

    ticket = ForeignKey("Ticket", null=False, related_name="ticketHistory")

    user = ForeignKey(User, null=False)
    action = TruncatedCharField(null=False, max_length=255)
    actionType = TruncatedCharField(
        max_length=32, null=True, choices=ACTION_TYPE, default="UpdateProperty"
    )
    ticketStatus = TruncatedCharField(null=True, max_length=32)
    date = DateTimeField(auto_now=True, null=False)

    @classmethod
    def log_ticket_action(cls, ticket=None, action=None, user=None, **kwargs):
        """
            Log ticket modifications
        """
        if not user:
            user = User.objects.get(username="abuse.robot")

        msg = get_log_message(ticket, action, user, **kwargs)

        cls.create(
            date=datetime.now(),
            ticket=ticket,
            user=user,
            action=msg,
            actionType="".join(word.capitalize() for word in action.split("_")),
            ticketStatus=ticket.status,
        )

        generates_kpi_infos(ticket, msg)

    @classmethod
    def log_new_report(cls, report):
        """
            Log report creation
        """
        from ..services.kpi import KPIService, KPIServiceException

        if not KPIService.is_implemented():
            return

        try:
            KPIService.new_report(report)
        except KPIServiceException:
            pass


def get_log_message(ticket, action, user, **kwargs):
    """
        Quite clean function
    """
    action_execution_date = kwargs.get("action_execution_date")
    action_name = kwargs.get("action_name")
    close_reason = kwargs.get("close_reason")
    email = kwargs.get("email")
    new_ticket = kwargs.get("new_ticket")
    report = kwargs.get("report")
    tag_name = kwargs.get("tag_name")
    previous_value = kwargs.get("previous_value")
    new_value = kwargs.get("new_value")
    field = kwargs.get("property")
    threshold_count = kwargs.get("threshold_count")
    threshold_interval = kwargs.get("threshold_interval")
    campaign_name = kwargs.get("campaign_name")

    msg = None
    if action in GENERIC_LOG_ACTION:
        msg = u"%s" % action.replace("_", " ")
    elif action in ("add_tag", "remove_tag"):
        msg = u"%s %s" % (action.replace("_", " "), tag_name)
    elif action == "validate_phishtocheck":
        msg = u"validate PhishToCheck report %d" % report.id
    elif action == "deny_phishtocheck":
        msg = u"deny PhishToCheck report %d" % report.id
    elif action == "change_status":
        reason = ", reason : %s" % close_reason if close_reason else ""
        wait = (
            " (for %d hour(s))" % (ticket.snoozeDuration / 3600)
            if new_value == "WaitingAnswer"
            else ""
        )
        msg = u"change status from {} to {}{}{}".format(
            previous_value, new_value, reason, wait
        )
    elif action == "change_treatedby":
        before = previous_value or "nobody"
        after = new_value or "nobody"
        msg = u"change treatedBy from %s to %s" % (before, after)
    elif action == "send_email":
        msg = u"sent an email to %s" % email
    elif action == "receive_email":
        msg = u"received an email from %s" % email
    elif action == "attach_report":
        if new_ticket:
            msg = u"create this ticket with report {} from {} ({}...)".format(
                report.id, report.provider.email, report.subject[:30]
            )
        else:
            msg = u"attach report {} from {} ({}...) to this ticket".format(
                report.id, report.provider.email, report.subject[:30]
            )
    elif action == "set_action":
        if action_execution_date:
            msg = u"set action: {}, execution {}".format(
                action_name, action_execution_date
            )
        else:
            msg = u"set action: %s, execution now" % action_name
    elif action == "cancel_action":
        msg = u"cancel action: %s" % action_name
    elif action == "update_property":
        msg = u"change %s from %s to %s" % (field, previous_value, new_value)
    elif action == "create_threshold":
        thres_msg = u"more than {} reports received in {} days".format(
            threshold_count, threshold_interval
        )
        msg = u"create this ticket with threshold ({})".format(thres_msg)
    elif action == "create_masscontact":
        msg = u"create this ticket with mass contact campaign %s" % campaign_name
    else:
        raise InvalidTicketHistoryAction("{} is not a valid log action".format(action))

    return msg


def generates_kpi_infos(ticket, action):
    """
        Generates KPI infos
    """
    from ..services.kpi import KPIService

    if not KPIService.is_implemented():
        return

    search_assign = re.search("change treatedby from nobody to", action.lower())
    if search_assign:
        generates_onassign_kpi(ticket)
        return

    search_closed = re.search("change status from .* to closed", action.lower())
    if search_closed:
        generates_onclose_kpi(ticket)
        return

    search_create = re.search("create this ticket with report", action.lower())
    if search_create:
        genereates_oncreate_kpi(ticket)
        return


def generates_onassign_kpi(ticket):
    """
        Kpi on ticket assignation
    """
    from ..services.kpi import KPIService, KPIServiceException

    try:
        KPIService.new_ticket_assign(ticket)
    except KPIServiceException:
        pass


def generates_onclose_kpi(ticket):
    """
        Kpi on ticket close
    """
    from ..services.kpi import KPIService, KPIServiceException

    try:
        KPIService.close_ticket(ticket)
    except KPIServiceException:
        pass


def genereates_oncreate_kpi(ticket):
    """
        Kpi on ticket creation
    """
    from ..services.kpi import KPIService, KPIServiceException

    try:
        KPIService.new_ticket(ticket)
    except KPIServiceException:
        pass
