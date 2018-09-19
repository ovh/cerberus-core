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
    Cerberus tickets manager
"""

import base64
import json
import operator
import time

from copy import deepcopy
from datetime import datetime, timedelta
from urllib import unquote

from django.contrib.auth.models import User
from django.core.exceptions import FieldError, MultipleObjectsReturned
from django.db import IntegrityError, transaction
from django.db.models import Count, FieldDoesNotExist, ObjectDoesNotExist, Q
from django.forms.models import model_to_dict
from netaddr import AddrConversionError, AddrFormatError, IPNetwork
from werkzeug.exceptions import BadRequest, Forbidden, InternalServerError, NotFound

from . import defendants as DefendantsController
from . import misc as MiscController
from . import providers as ProvidersController
from .constants import (
    IP_CIDR_RE,
    TICKET_FIELDS,
    TICKET_FILTER_MAPPING,
    TICKET_UPDATE_VALID_FIELDS,
    TICKET_BULK_VALID_FIELDS,
    TICKET_BULK_VALID_STATUS,
    TICKET_MODIFICATION_INVALID_FIELDS,
    TICKET_STATUS,
)
from .ticketscheduling import TicketSchedulingAlgorithms
from ...models import (
    AbusePermission,
    Defendant,
    History,
    Proof,
    Report,
    Resolution,
    Service,
    ServiceAction,
    ServiceActionJob,
    Tag,
    Ticket,
    TicketComment,
    AttachedDocument,
    StarredTicket,
)
from ...services.crm import CRMService, CRMServiceException
from ...services.action import ActionService, ActionServiceException
from ...services.email import EmailService, EmailServiceException
from ...services.search import SearchService, SearchServiceException
from ...services.storage import StorageService, StorageServiceException
from ...tasks import cancel, enqueue


def get_tickets(**kwargs):
    """
        Main endpoint, get all tickets from db and eventually contains
        filters (json format) in query like sortBy, where ...
    """

    # Parse filters from request
    user = kwargs["user"]
    filters = {}
    if kwargs.get("filters"):
        try:
            filters = json.loads(unquote(unquote(kwargs["filters"])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex.message))
    try:
        limit = int(filters["paginate"]["resultsPerPage"])
        offset = int(filters["paginate"]["currentPage"])
    except KeyError:
        limit = 10
        offset = 1

    # Generate Django filter based on parsed filters
    try:
        where = _generate_request_filters(filters, user, kwargs.get("treated_by"))
    except (
        AttributeError,
        KeyError,
        IndexError,
        FieldError,
        SyntaxError,
        TypeError,
        ValueError,
    ) as ex:
        raise BadRequest(str(ex.message))

    # Try to identify sortby in request
    sort = []
    if filters.get("sortBy") and filters["sortBy"].get("attachedReportsCount"):
        if filters["sortBy"]["attachedReportsCount"] < 0:
            sort.append("-attachedReportsCount")
        else:
            sort.append("attachedReportsCount")
        filters["sortBy"].pop("attachedReportsCount", None)

    try:
        sort += ["-" + k if v < 0 else k for k, v in filters["sortBy"].iteritems()]
    except KeyError:
        sort += ["id"]

    try:
        fields = filters["queryFields"]
    except KeyError:
        fields = [fld.name for fld in Ticket._meta.fields]

    fields.append("id")
    try:
        fields = list(set(fields))
        nb_record_filtered = Ticket.filter(where).distinct().count()
        tickets = (
            Ticket.filter(where)
            .values(*fields)
            .annotate(attachedReportsCount=Count("reportTicket"))
            .order_by(*sort)
        )
        tickets = tickets[(offset - 1) * limit : limit * offset]
        len(tickets)  # Force django to evaluate query now
    except (
        AttributeError,
        KeyError,
        IndexError,
        FieldError,
        SyntaxError,
        TypeError,
        ValueError,
    ) as ex:
        raise BadRequest(str(ex.message))

    _format_ticket_response(tickets, user)
    return list(tickets), nb_record_filtered


def _generate_request_filters(filters, user=None, treated_by=None):
    """
        Generates filters base on filter query string
    """
    where = [Q()]
    if treated_by:
        where.append(Q(treatedBy=treated_by))

    # Add SearchService results if fulltext search
    try:
        for field in filters["where"]["like"]:
            for key, value in field.iteritems():
                if key == "fulltext":
                    if SearchService.is_implemented():
                        _add_search_filters(filters, value[0])
                    filters["where"]["like"].remove({key: value})
                    break
    except KeyError:
        pass

    # Generates Django query filter
    if "where" in filters and filters["where"]:
        keys = set(k for k in filters["where"])
        if "in" in keys:
            for param in filters["where"]["in"]:
                for key, val in param.iteritems():
                    field = reduce(
                        lambda a, kv: a.replace(*kv), TICKET_FILTER_MAPPING, key
                    )
                    where.append(reduce(operator.or_, [Q(**{field: i}) for i in val]))
        if "like" in keys:
            like = []
            for param in filters["where"]["like"]:
                for key, val in param.iteritems():
                    field = reduce(
                        lambda a, kv: a.replace(*kv), TICKET_FILTER_MAPPING, key
                    )
                    field = field + "__icontains"
                    like.append(Q(**{field: val[0]}))
            if like:
                where.append(reduce(operator.or_, like))
    else:
        # All except closed
        where.append(~Q(status="Closed"))

    # Filter allowed category for this user
    user_specific_where = []
    abuse_permissions = AbusePermission.filter(user=user.id)

    for perm in abuse_permissions:
        if perm.profile.name == "Expert":
            user_specific_where.append(Q(category=perm.category))
        elif perm.profile.name in ("Advanced", "Read-only", "Beginner"):
            user_specific_where.append(Q(category=perm.category, confidential=False))

    if user_specific_where:
        user_specific_where = reduce(operator.or_, user_specific_where)
        where.append(user_specific_where)
    else:
        # If no category allowed
        where.append(Q(category=None))
    # Aggregate all filters
    where = reduce(operator.and_, where)
    return where


def _format_ticket_response(tickets, user):
    """ Convert datetime object and add flat foreign key
    """
    for ticket in tickets:

        # Flat foreign models
        if ticket.get("defendant"):
            defendant = Defendant.get(id=ticket["defendant"])
            ticket["defendant"] = model_to_dict(defendant, exclude=["tags"])
            ticket["defendant"]["email"] = defendant.details.email
        if ticket.get("service"):
            ticket["service"] = model_to_dict(Service.get(id=ticket["service"]))
        if ticket.get("treatedBy"):
            ticket["treatedBy"] = User.objects.get(id=ticket["treatedBy"]).username
        if ticket.get("tags"):
            tags = Ticket.get(id=ticket["id"]).tags.all()
            ticket["tags"] = [model_to_dict(tag) for tag in tags]
        ticket["commentsCount"] = TicketComment.filter(ticket=ticket["id"]).count()
        ticket["starredByMe"] = StarredTicket.filter(
            ticket_id=ticket["id"], user=user
        ).exists()


def _add_search_filters(filters, query):
    """
        Add SearchService response to filters
    """
    search_query = query
    if IP_CIDR_RE.match(query):
        try:  # Try to parse IP/CIDR search
            network = IPNetwork(query)
            if network.size <= 4096:
                search_query = " ".join([str(host) for host in network.iter_hosts()])
                search_query = search_query if search_query else query
        except (AttributeError, IndexError, AddrFormatError, AddrConversionError):
            pass
    try:
        reports = SearchService.search_reports(search_query)
        if not reports:
            reports = [None]
    except SearchServiceException:
        return

    if "in" in filters["where"]:
        for field in filters["where"]["in"]:
            for key, values in field.iteritems():
                if key == "reportTicket__id" and values:
                    reports.extend(values)
                    filters["where"]["in"].remove({key: values})
            filters["where"]["in"].append({"reportTicket__id": reports})
    else:
        filters["where"]["in"] = [{"reportTicket__id": reports}]


def show(ticket_id, user):
    """ Get a ticket
    """
    try:
        ticket = Ticket.get(id=ticket_id)
        just_assigned = False
        if not ticket.treatedBy:
            just_assigned = assign_if_not(ticket, user)
        ticket_dict = Ticket.filter(id=ticket_id).values(*TICKET_FIELDS)[0]
    except (IndexError, ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    # Add related infos
    if ticket.treatedBy:
        ticket_dict["treatedBy"] = ticket.treatedBy.username
    if ticket.defendant:
        ticket_dict["defendant"] = DefendantsController.show(ticket.defendant.id)
    if ticket.action:
        ticket_dict["action"] = model_to_dict(ServiceAction.get(id=ticket.action.id))
    if ticket.service:
        ticket_dict["service"] = model_to_dict(Service.get(id=ticket.service.id))
    if ticket.jobs:
        ticket_dict["jobs"] = []
        for job in ticket.jobs.all():
            info = model_to_dict(job)
            ticket_dict["jobs"].append(info)

    ticket_reports_id = (
        ticket.reportTicket.all().values_list("id", flat=True).distinct()
    )

    ticket_dict["starredByMe"] = StarredTicket.filter(ticket=ticket, user=user).exists()

    ticket_dict["comments"] = _get_ticket_comments(ticket)
    ticket_dict["history"] = _get_ticket_history(ticket)
    ticket_dict["attachedReportsCount"] = ticket.reportTicket.count()
    ticket_dict["tags"] = _get_ticket_tags(ticket, ticket_reports_id)
    ticket_dict["justAssigned"] = just_assigned

    return ticket_dict


def _get_ticket_comments(ticket):
    """
        Get ticket comments..
    """
    return [
        {
            "id": c.comment.id,
            "user": c.comment.user.username,
            "date": time.mktime(c.comment.date.timetuple()),
            "comment": c.comment.comment,
        }
        for c in TicketComment.filter(ticket=ticket.id).order_by("-comment__date")
    ]


def _get_ticket_history(ticket):
    """
        Get ticket history..
    """
    history = (
        History.filter(ticket=ticket.id)
        .values_list("user__username", "date", "action")
        .order_by("-date")
    )
    return [
        {"username": username, "date": time.mktime(date.timetuple()), "action": action}
        for username, date, action in history
    ]


def _get_ticket_tags(ticket, ticket_reports_id):
    """
        Get ticket tags..
    """
    report_tags = Tag.filter(report__id__in=ticket_reports_id).distinct()
    tags = list(set(list(set(ticket.tags.all())) + list(set(report_tags))))
    return [model_to_dict(tag) for tag in tags]


def get_ticket_attachments(ticket_id):
    """
        Get ticket attachments..
    """
    try:
        ticket = Ticket.get(id=ticket_id)
    except (IndexError, ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    ticket_reports_id = (
        ticket.reportTicket.all().values_list("id", flat=True).distinct()
    )

    attachments = AttachedDocument.filter(report__id__in=ticket_reports_id).distinct()
    attachments = list(attachments)
    attachments.extend(ticket.attachments.all())
    attachments = list(set(attachments))
    attachments = [model_to_dict(attach) for attach in attachments]
    return attachments


def assign_if_not(ticket, user):
    """
        If ticket is not assigned and user not just set ticket owner to nobody
        assign ticket to current user
    """
    try:
        perm = AbusePermission.get(user=user, category=ticket.category)
        if perm.profile.name == "Read-only":
            return False
    except ObjectDoesNotExist:
        return False

    assigned = False
    delta = datetime.now() - timedelta(seconds=15)
    just_unassigned = ticket.ticketHistory.filter(
        date__gt=delta, action__icontains="to nobody"
    ).order_by("-date")[:1]
    if not ticket.treatedBy and not ticket.protected and not just_unassigned:
        ticket.treatedBy = user
        ticket.save()
        History.log_ticket_action(
            ticket=ticket, action="change_treatedby", user=user, new_value=user.username
        )
        assigned = True
    return assigned


def create(body, user):
    """ Create a ticket from a report or attach it
        if ticket with same defendant/category already exists
    """
    try:
        if body["status"].lower() not in ("new", "attached"):
            raise BadRequest("Can not create a ticket with this status")
        report = Report.get(id=body["id"])
    except (KeyError, ObjectDoesNotExist):
        raise BadRequest("Invalid or missing report id")

    MiscController.check_perms(method="POST", user=user, report=report.id)

    # Retrieve foreign model from body
    defendant = None
    if report.defendant:
        try:
            defendant = DefendantsController.get_or_create(
                customer_id=report.defendant.customerId
            )
            if not defendant:
                raise BadRequest("Defendant not found")
        except KeyError:
            raise BadRequest("Missing id in defendant object")

    service = None
    if report.service:
        try:
            service = Service.get(id=report.service.id, name=report.service.name)
        except (KeyError, ObjectDoesNotExist):
            raise BadRequest("Invalid service or missing id in service object")

    new_ticket = False
    ticket = None
    # Try to attach to existing
    if all((defendant, service, report.category)):
        ticket = Ticket.search(defendant, report.category, service)

    # Else creates ticket
    if not ticket:
        ticket = Ticket.create_ticket(
            defendant, report.category, service, priority=report.provider.priority
        )
        new_ticket = True

    History.log_ticket_action(
        ticket=ticket,
        action="attach_report",
        user=user,
        report=report,
        new_ticket=new_ticket,
    )

    report.status = "Attached"
    report.ticket = ticket
    report.save()
    ticket.set_higher_priority()

    # If new report, try to attach existing reports with status "New" to this new created ticket
    if ticket:
        for rep in ticket.reportTicket.filter(~Q(id__in=[report.id])):
            History.log_ticket_action(
                ticket=ticket,
                action="attach_report",
                user=user,
                report=report,
                new_ticket=False,
            )

    resp = show(ticket.id, user)
    return resp


def update(ticket, body, user, bulk=False):
    """
        Update a ticket
    """
    allowed, body = _precheck_user_fields_update_authorizations(user, body)
    if not allowed:
        raise Forbidden("You are not allowed to edit any fields")

    if not isinstance(ticket, Ticket):
        try:
            ticket = Ticket.get(id=ticket)
        except (ObjectDoesNotExist, ValueError):
            raise NotFound("Not Found")

    if "defendant" in body and body["defendant"] != ticket.defendant:
        body["defendant"] = update_ticket_defendant(ticket, body["defendant"])

    if "category" in body and body["category"] != ticket.category:
        try:
            ticket.reportTicket.update(category=body["category"])
        except IntegrityError:
            raise BadRequest("Invalid category")

    # If the user is a Beginner, he does not have the rights to modify these infos
    if user.abusepermission_set.filter(
        category=ticket.category, profile__name="Beginner"
    ).count():
        body.pop("escalated", None)
        body.pop("moderation", None)

    if not ticket.escalated and body.get("escalated"):
        body["treatedBy"] = None

    if (
        "treatedBy" in body
        and ticket.treatedBy
        and ticket.protected
        and ticket.treatedBy.username != body["treatedBy"]
    ):
        raise BadRequest("Ticket is protected")

    # remove invalid fields
    body = {k: v for k, v in body.iteritems() if k in TICKET_UPDATE_VALID_FIELDS}

    if body.get("treatedBy"):
        body["treatedBy"] = User.objects.get(username=body["treatedBy"])

    body["modificationDate"] = datetime.now()
    old = deepcopy(ticket)

    try:
        Ticket.filter(pk=ticket.pk).update(**body)
        ticket = Ticket.get(pk=ticket.pk)
        actions = _get_modifications(old, ticket, user)

        for action in actions:
            History.log_ticket_action(**action)

    except (
        KeyError,
        FieldDoesNotExist,
        FieldError,
        IntegrityError,
        TypeError,
        ValueError,
    ) as ex:
        raise BadRequest(str(ex.message))

    if bulk:
        return None

    return show(ticket.id, user)


def _get_modifications(old, new, user):
    """ Track ticket changes
    """
    actions = []
    if getattr(old, "category") != getattr(new, "category"):
        old_value = (
            getattr(old, "category").name
            if getattr(old, "category") is not None
            else "nothing"
        )
        new_value = (
            getattr(new, "category").name
            if getattr(new, "category") is not None
            else "nothing"
        )
        actions.append(
            {
                "ticket": new,
                "action": "update_property",
                "user": user,
                "property": "category",
                "previous_value": old_value,
                "new_value": new_value,
            }
        )
    if getattr(old, "defendant") != getattr(new, "defendant"):
        old_value = (
            getattr(old, "defendant").customerId
            if getattr(old, "defendant") is not None
            else "nobody"
        )
        new_value = (
            getattr(new, "defendant").customerId
            if getattr(new, "defendant") is not None
            else "nobody"
        )
        actions.append(
            {
                "ticket": new,
                "action": "update_property",
                "user": user,
                "property": "defendant",
                "previous_value": old_value,
                "new_value": new_value,
            }
        )
    if getattr(old, "treatedBy") != getattr(new, "treatedBy"):
        old_value = (
            getattr(old, "treatedBy").username
            if getattr(old, "treatedBy") is not None
            else "nobody"
        )
        new_value = (
            getattr(new, "treatedBy").username
            if getattr(new, "treatedBy") is not None
            else "nobody"
        )
        actions.append(
            {
                "ticket": new,
                "action": "update_property",
                "user": user,
                "property": "treatedBy",
                "previous_value": old_value,
                "new_value": new_value,
            }
        )

    for field in set(TICKET_FIELDS) - set(TICKET_MODIFICATION_INVALID_FIELDS):
        if getattr(old, field) != getattr(new, field):
            actions.append(
                {
                    "ticket": new,
                    "action": "update_property",
                    "user": user,
                    "property": field,
                    "previous_value": getattr(old, field),
                    "new_value": getattr(new, field),
                }
            )
    return actions


def update_snooze_duration(ticket_id, body, user):
    """ Update ticket snooze duration
    """
    try:
        ticket = Ticket.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Not Found")

    try:
        data = {"snoozeDuration": body["snoozeDuration"]}

        if data["snoozeDuration"] == 0 and ticket.status == "WaitingAnswer":
            ticket.previousStatus = ticket.status
            ticket.status = "Alarm"
            ticket.save()

        if int(data["snoozeDuration"]) > 10000000:
            raise BadRequest("Invalid duration")

        # Delay jobs
        new_duration = int(data["snoozeDuration"])
        if new_duration > ticket.snoozeDuration:
            delay = new_duration - ticket.snoozeDuration
            delay = timedelta(seconds=delay)
            enqueue("ticket.delay_jobs", ticket=ticket.id, delay=delay, back=False)
        else:
            delay = ticket.snoozeDuration - new_duration
            delay = timedelta(seconds=delay)
            enqueue("ticket.delay_jobs", ticket=ticket.id, delay=delay, back=True)
        return _update_duration(ticket, data, user)
    except (KeyError, ValueError) as ex:
        raise BadRequest(str(ex.message))


def update_pause_duration(ticket_id, body, user):
    """ Update ticket pause duration
    """
    try:
        ticket = Ticket.get(id=ticket_id)
        if ticket.status != "Paused":
            raise BadRequest("Ticket is not paused")
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Not Found")

    try:
        data = {"pauseDuration": body["pauseDuration"]}
        if int(data["pauseDuration"]) > 10000000:
            raise BadRequest("Invalid duration")

        # Delay jobs
        new_duration = int(data["pauseDuration"])
        if new_duration > ticket.pauseDuration:
            delay = new_duration - ticket.pauseDuration
            delay = timedelta(seconds=delay)
            enqueue("ticket.delay_jobs", ticket=ticket.id, delay=delay, back=False)
        else:
            delay = ticket.pauseDuration - new_duration
            delay = timedelta(seconds=delay)
            enqueue("ticket.delay_jobs", ticket=ticket.id, delay=delay, back=True)
        return _update_duration(ticket, data, user)
    except (KeyError, ValueError) as ex:
        raise BadRequest(str(ex.message))


def _update_duration(ticket, data, user):
    """ Generic update for duration
    """
    try:
        key = data.keys()[0]
        previous = getattr(ticket, key)
        data[key.replace("Duration", "Start")] = datetime.now()

        Ticket.filter(pk=ticket.pk).update(**data)
        ticket = Ticket.get(pk=ticket.pk)

        History.log_ticket_action(
            ticket=ticket,
            action="update_property",
            user=user,
            property=key.replace("Duration", ""),
            previous_value=str(timedelta(seconds=previous)),
            new_value=str(timedelta(seconds=getattr(ticket, key))),
        )

    except (FieldDoesNotExist, FieldError, IntegrityError, TypeError, ValueError) as ex:
        raise BadRequest(str(ex.message))

    return show(ticket.id, user)


def update_ticket_defendant(ticket, defendant):
    """ Update defendant infos
    """
    defendant_obj = None
    if defendant is None:
        ticket.service = None
        ticket.save()
        for report in ticket.reportTicket.all():  # flushing tickets's reports defendant
            report.service = None
            report.defendant = None
            report.reportItemRelatedReport.all().delete()
            report.save()
    else:
        try:
            defendant_obj = DefendantsController.get_or_create(
                customer_id=defendant["customerId"]
            )
            if not defendant_obj:
                raise BadRequest("Defendant not found")
        except KeyError:
            raise BadRequest("Missing customerId or id in defendant body")

        # Cascade update
        if ticket.defendant != defendant:
            ticket.reportTicket.update(defendant=defendant_obj.id)

    return defendant_obj


def get_providers(ticket_id):
    """ Get ticket's providers
    """
    try:
        ticket = Ticket.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    emails = set(ticket.reportTicket.all().values_list("provider__pk", flat=True))
    providers = [ProvidersController.show(email) for email in emails]
    contacted = ticket.get_emailed_providers()

    for prov in providers:
        prov["contacted"] = prov["email"] in contacted

    return providers


def get_priorities():
    """ Get ticket model priorities
    """
    return [{"label": p[0]} for p in Ticket.TICKET_PRIORITY]


def get_proof(ticket_id):
    """ Get ticket proof
    """
    try:
        ticket = Ticket.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    return [model_to_dict(p) for p in ticket.proof.all()]


def add_proof(ticket_id, body, user):
    """ Add proof to ticket
    """
    try:
        ticket = Ticket.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    if isinstance(body, dict):
        body = [body]

    if not isinstance(body, list):
        raise BadRequest("Invalid body, expecting object or list")

    for param in body:
        try:
            ticket.proof.create(**param)
            ticket.save()
            History.log_ticket_action(ticket=ticket, action="add_proof", user=user)
        except (
            KeyError,
            FieldDoesNotExist,
            FieldError,
            IntegrityError,
            TypeError,
            ValueError,
        ) as ex:
            raise BadRequest(str(ex.message))

    return {"message": "Proof successfully added to ticket"}


def update_proof(ticket_id, proof_id, body, user):
    """ Update proof
    """
    ticket = None
    try:
        ticket = Ticket.get(id=ticket_id)
        Proof.get(id=proof_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Not Found")

    try:
        body.pop("id", None)
        body.pop("ticket", None)
        ticket.proof.update(**body)
        ticket.save()
        History.log_ticket_action(ticket=ticket, action="update_proof", user=user)
    except (
        KeyError,
        FieldDoesNotExist,
        FieldError,
        IntegrityError,
        TypeError,
        ValueError,
    ) as ex:
        raise BadRequest(str(ex.message))
    return {"message": "Proof successfully updated"}


def delete_proof(ticket_id, proof_id, user):
    """ Delete proof
    """
    try:
        ticket = Ticket.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    try:
        proof = ticket.proof.get(id=proof_id)
        proof.delete()
        History.log_ticket_action(ticket=ticket, action="delete_proof", user=user)
    except (
        ObjectDoesNotExist,
        KeyError,
        FieldDoesNotExist,
        FieldError,
        IntegrityError,
        TypeError,
        ValueError,
    ) as ex:
        raise BadRequest(str(ex.message))
    return {"message": "Proof successfully deleted"}


def add_items_to_proof(ticket_id, user):
    """
        Add all `abuse.models.ReportItems`
        to `abuse.models.Ticket`'s `abuse.models.Proof`
    """
    try:
        ticket = Ticket.get(id=ticket_id)
        if not all((ticket.defendant, ticket.service)):
            raise BadRequest("Need defendant")
    except (IndexError, ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    items = (
        ticket.reportTicket.all()
        .values_list("reportItemRelatedReport__rawItem", flat=True)
        .distinct()
    )

    # Check items current state
    try:
        services = CRMService.get_services_from_items(ips=items, urls=items, fqdn=items)
    except CRMServiceException:
        raise InternalServerError("Unknown exception while identifying defendant")

    _create_proof(ticket, services)

    History.log_ticket_action(ticket=ticket, action="add_proof", user=user)

    return {"message": "Proof successfully updated"}


def _create_proof(ticket, services):

    for service in services:
        if (
            service["defendant"]["customerId"] == ticket.defendant.customerId
            and service["service"]["serviceId"] == ticket.service.serviceId
        ):
            items = [
                item for sub in services[0]["items"].values() for item in sub if sub
            ]
            for item in items:
                proof, _ = Proof.get_or_create(ticket=ticket, content=item)


def update_status(ticket, status, body, user):
    """
        Update ticket status
    """
    if not _precheck_user_status_update_authorizations(user, status):
        raise Forbidden("You are not allowed to set this status")

    try:
        status = status.lower()
    except AttributeError:
        raise BadRequest("Invalid status")

    if status not in TICKET_STATUS and status != "unpaused":
        raise BadRequest("Invalid status")

    if not isinstance(ticket, Ticket):
        try:
            ticket = Ticket.get(id=ticket)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            raise NotFound("Ticket not found")

    if not status == "waitinganswer" and status == ticket.status.lower():
        raise BadRequest("Ticket had already this status")

    try:
        if status == "paused":
            if int(body["pauseDuration"]) > 10000000:
                raise BadRequest("Invalid pause duration")
            ticket.pause(int(body["pauseDuration"]))
        elif status == "unpaused":
            ticket.unpause()
        elif status == "waitinganswer":
            if int(body["snoozeDuration"]) > 10000000:
                raise BadRequest("Invalid snooze duration")
            ticket.snoozeDuration = int(body["snoozeDuration"])
            ticket.snoozeStart = datetime.now()
            ticket.set_status("WaitingAnswer", user=user)
        elif status == "closed":
            resolution = Resolution.get(id=int(body["resolution"]))
            ticket.resolution = resolution
            ticket.save(update_fields=["resolution"])
            ticket.set_status(
                "Closed", user=user, resolution_codename=resolution.codename
            )
        elif status == "reopened":
            ticket.set_status("Reopened", user=user)
    except Exception as ex:
        raise BadRequest("Missing or invalid parameter(s): %s" % str(ex))

    return {"message": "Ticket update"}


@transaction.atomic
def bulk_update(body, user, method):
    """
        Add or update infos for multiple tickets
    """
    tickets = _check_bulk_conformance(body, user, method)

    for ticket in tickets:
        assign_if_not(ticket, user)

    # Update status
    if "status" in body["properties"]:
        if body["properties"]["status"].lower() not in TICKET_BULK_VALID_STATUS:
            raise BadRequest("Status not supported")

        valid_fields = ("pauseDuration", "resolution")
        properties = {
            k: v for k, v in body["properties"].iteritems() if k in valid_fields
        }

        for ticket in tickets:
            update_status(ticket, body["properties"]["status"], properties, user)

    # Update general fields
    properties = {
        k: v for k, v in body["properties"].iteritems() if k in TICKET_BULK_VALID_FIELDS
    }

    if properties:
        for ticket in tickets:
            update(ticket, properties, user, bulk=True)

    return {"message": "Ticket(s) successfully updated"}


@transaction.atomic
def bulk_delete(body, user, method):
    """
        Delete infos from multiple tickets
    """
    tickets = _check_bulk_conformance(body, user, method)

    # Update tags
    try:
        if "tags" in body["properties"] and isinstance(
            body["properties"]["tags"], list
        ):
            for ticket in tickets:
                for tag in body["properties"]["tags"]:
                    remove_tag(ticket.id, tag["id"], user)
    except (KeyError, TypeError, ValueError):
        raise BadRequest("Invalid or missing tag(s) id")

    return {"message": "Ticket(s) successfully updated"}


def _check_bulk_conformance(body, user, method):
    """
        Check request conformance for bulk
    """
    if not body.get("tickets") or not body.get("properties"):
        raise BadRequest("Missing tickets or properties in body")

    try:
        tickets = Ticket.filter(id__in=list(body["tickets"]))
    except (AttributeError, TypeError, ValueError, KeyError):
        raise BadRequest("Invalid ticket(s) id")

    for ticket in tickets:
        MiscController.check_perms(method=method, user=user, ticket=ticket.id)

    return tickets


def add_tag(ticket_id, body, user):
    """ Add ticket tag
    """
    try:
        tag = Tag.get(**body)
        ticket = Ticket.get(id=ticket_id)

        if ticket.__class__.__name__ != tag.tagType:
            raise BadRequest("Invalid tag for ticket")

        ticket.tags.add(tag)
        ticket.save()
        History.log_ticket_action(
            ticket=ticket, action="add_tag", user=user, tag_name=tag.name
        )
    except MultipleObjectsReturned:
        raise BadRequest("Please use tag id")
    except (KeyError, FieldError, IntegrityError, ObjectDoesNotExist, ValueError):
        raise NotFound("Tag or ticket not found")
    return {"message": "Tag successfully added"}


def remove_tag(ticket_id, tag_id, user):
    """ Remove ticket tag
    """
    try:
        tag = Tag.get(id=tag_id)
        ticket = Ticket.get(id=ticket_id)

        if ticket.__class__.__name__ != tag.tagType:
            raise BadRequest("Invalid tag for ticket")

        ticket.tags.remove(tag)
        ticket.save()
        History.log_ticket_action(
            ticket=ticket, action="remove_tag", user=user, tag_name=tag.name
        )

    except (ObjectDoesNotExist, FieldError, IntegrityError, ValueError):
        raise NotFound("Not Found")
    return {"message": "Tag successfully removed"}


def get_actions_list(ticket_id, user):
    """
        List possible actions for ticket
    """
    try:
        ticket = Ticket.get(id=ticket_id)
        if not ticket.service or not ticket.defendant:
            return []
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    try:
        perm = AbusePermission.get(user=user, category=ticket.category)
        authorized = list(set(perm.profile.actions.all().values_list("id", flat=True)))
    except ObjectDoesNotExist:
        raise Forbidden("You can not interact with this ticket")

    try:
        actions = ActionService.list_actions_for_ticket(ticket)
    except ActionServiceException:
        raise InternalServerError("Unable to list actions for this ticket")

    actions = [model_to_dict(action) for action in actions if action.id in authorized]
    return actions


def cancel_asynchronous_job(ticket_id, job_id, user):
    """ Cancel task on ticket
    """
    try:
        ticket = Ticket.get(id=ticket_id)
        job = ServiceActionJob.get(id=job_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket or job not found")

    if ticket.action:
        History.log_ticket_action(
            ticket=ticket,
            action="cancel_action",
            user=user,
            action_name=ticket.action.name,
        )

    cancel(job.asynchronousJobId)
    ServiceActionJob.filter(asynchronousJobId=job.asynchronousJobId).update(
        status="cancelled"
    )
    ticket.save()
    return {"message": "Task successfully canceled"}


def get_jobs_status(ticket_id):
    """
        Get actions todo status
    """
    try:
        ticket = Ticket.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    resp = []
    jobs = ticket.jobs.all().order_by("creationDate")
    for job in jobs:
        info = model_to_dict(job)
        if info.get("action"):
            info["action"] = model_to_dict(ServiceAction.get(id=info["action"]))
        resp.append(info)

    return resp


def get_todo_tickets(**kwargs):
    """
        Get TODO tickets
    """
    # Parse filters from request
    filters = {}
    if kwargs.get("filters"):
        try:
            filters = json.loads(unquote(unquote(kwargs["filters"])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex.message))

    user = kwargs["user"]
    try:
        scheduling_algo = user.operator.role.modelsAuthorizations["ticket"][
            "schedulingAlgorithm"
        ]
        tickets, nb_record = TicketSchedulingAlgorithms[scheduling_algo].get_tickets(
            user=user, filters=filters
        )
        _format_ticket_response(tickets, user)
    except (ObjectDoesNotExist, KeyError):
        tickets = []
        nb_record = 0

    return {"tickets": list(tickets), "ticketsCount": nb_record}


def get_emails(ticket_id):
    """
        Get all emails for this tickets
    """
    ticket = None
    try:
        ticket = Ticket.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    try:
        emails = EmailService.get_emails(ticket)
        response = []
        for email in emails:
            attachments = _get_email_attachments(email, ticket)
            response.append(
                {
                    "body": email.body,
                    "created": email.created,
                    "from": email.sender,
                    "subject": email.subject,
                    "to": email.recipient,
                    "category": email.category,
                    "attachments": attachments,
                }
            )
        return response
    except (KeyError, EmailServiceException) as ex:
        raise InternalServerError(str(ex))


def _get_email_attachments(email, ticket):

    attachments = []
    if not email.attachments:
        return attachments

    filters = [
        {"name": a["filename"], "filetype": a["content_type"]}
        for a in email.attachments
    ]

    for attach in filters:
        for att in ticket.attachments.filter(**attach):
            desc = model_to_dict(att)
            if desc not in attachments:
                attachments.append(desc)

    return attachments


def _precheck_user_fields_update_authorizations(user, body):
    """
       Check if user's update paramaters are allowed
    """
    authorizations = user.operator.role.modelsAuthorizations
    if authorizations.get("ticket") and authorizations["ticket"].get("fields"):
        body = {
            k: v for k, v in body.iteritems() if k in authorizations["ticket"]["fields"]
        }
        if not body:
            return False, body
        return True, body
    return False, body


def _precheck_user_status_update_authorizations(user, status):
    """
       Check if user's update paramaters are allowed
    """
    authorizations = user.operator.role.modelsAuthorizations
    if authorizations.get("ticket") and authorizations["ticket"].get("status"):
        return status.lower() in authorizations["ticket"]["status"]

    return False


def get_timeline(ticket_id, **kwargs):
    """
        Get ̀àbuse.models.Ticket` history and activities
    """
    try:
        ticket = Ticket.get(id=ticket_id)
    except (IndexError, ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    # Parse filters from request
    filters = {}
    if kwargs.get("filters"):
        try:
            filters = json.loads(unquote(unquote(kwargs["filters"])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex.message))
    try:
        limit = int(filters["paginate"]["resultsPerPage"])
        offset = int(filters["paginate"]["currentPage"])
    except KeyError:
        limit = 10
        offset = 1

    with_meta = False
    if filters.get("withMetadata"):
        with_meta = True

    order_by = "date" if filters.get("reverse") else "-date"

    history = _get_timeline_history(ticket, with_meta, order_by, limit, offset)
    return history


def _get_timeline_history(ticket, with_meta, order_by, limit, offset):

    history = (
        ticket.ticketHistory.all()
        .values_list("user__username", "date", "action", "actionType")
        .order_by(order_by)[(offset - 1) * limit : limit * offset]
    )

    history = [
        {"username": username, "date": date, "log": log, "actionType": action_type}
        for username, date, log, action_type in history
    ]

    if not with_meta:
        return history

    for entry in history:
        entry["metadata"] = None
        if entry["actionType"] in ["AddComment", "UpdateComment"]:
            comment = (
                ticket.comments.filter(
                    comment__date__range=(
                        entry["date"] - timedelta(seconds=1),
                        entry["date"] + timedelta(seconds=1),
                    )
                )
                .values_list("comment__comment", flat=True)
                .last()
            )
            entry["metadata"] = {"key": "comment", "value": comment}
        elif entry["actionType"] in ["AddItem", "UpdateItem"]:
            item = (
                ticket.reportTicket.filter(
                    reportItemRelatedReport__date__range=(
                        entry["date"] - timedelta(seconds=1),
                        entry["date"] + timedelta(seconds=1),
                    )
                )
                .values_list("reportItemRelatedReport__rawItem", flat=True)
                .last()
            )
            entry["metadata"] = {"key": "item", "value": item}

    return history


def get_attachment(ticket_id, attachment_id):
    """
        Get given abuse.models.AttachedDocument`
        for given `abuse.models.Ticket`
    """
    try:
        Ticket.filter(id=ticket_id)
        attachment = AttachedDocument.get(id=attachment_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket or attachment not found")

    resp = None
    try:
        raw = StorageService.read(attachment.filename)
        resp = {
            "raw": base64.b64encode(raw),
            "filetype": str(attachment.filetype),
            "filename": attachment.name.encode("utf-8"),
        }
    except StorageServiceException:
        pass

    if not resp:
        raise NotFound("Raw attachment not found")

    return resp


def star_ticket_management(ticket_id, user, method="POST"):
    """
        Star/Unstar given `abuse.models.Ticket`
        for given `abuse.models.User`
    """
    try:
        ticket = Ticket.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    try:
        if method == "POST":
            StarredTicket.create(user=user, ticket=ticket)
            return {"message": "Ticket successfully starred"}
        elif method == "DELETE":
            StarredTicket.filter(user=user, ticket=ticket).delete()
            return {"message": "Ticket successfully unstarred"}
        else:
            raise BadRequest("Unsupported operation")
    except IntegrityError:
        raise BadRequest("You have already starred this ticket")
