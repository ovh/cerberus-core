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
    Cerberus report controller
"""

import json
import operator
import re
from base64 import b64encode
from Queue import Queue
from threading import Thread
from urllib import unquote

import html2text
from django.core.exceptions import FieldError, MultipleObjectsReturned
from django.db import IntegrityError, transaction
from django.db.models import FieldDoesNotExist, ObjectDoesNotExist, Q
from django.forms.models import model_to_dict
from netaddr import AddrConversionError, AddrFormatError, IPNetwork
from werkzeug.exceptions import BadRequest, Forbidden, InternalServerError, NotFound

from . import defendants as DefendantsController
from . import misc as MiscController
from . import providers as ProvidersController
from . import reportitems as ReportItemsController
from . import tickets as TicketsController
from .constants import (
    IP_CIDR_RE,
    REPORT_STATUS,
    REPORT_FILTER_MAPPING,
    REPORT_FIELDS,
    REPORT_ATTACHMENT_FIELDS,
    ALL_CATEGORIES,
)
from ...models import (
    AbusePermission,
    Defendant,
    Report,
    ReportItem,
    Service,
    Tag,
    Ticket,
)
from ...services.search import SearchService, SearchServiceException
from ...services.storage import StorageService, StorageServiceException
from ...parsers import Parser
from ...tasks import enqueue

html2text.ignore_images = True
html2text.images_to_alt = True
html2text.ignore_links = True


def get_reports(**kwargs):
    """ Main endpoint, get all reports from db and eventually contains
        filters (json format) in query like sortBy, where ...
    """
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

    # Generate Django filter based on parsed filters
    try:
        where = _generate_request_filters(filters, kwargs["user"])
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
    try:
        sort = ["-" + k if v < 0 else k for k, v in filters["sortBy"].iteritems()]
    except (FieldError, KeyError):
        sort = ["-receivedDate"]

    sort.append("id")

    if "queryFields" in filters:
        fields = filters["queryFields"]
    else:
        fields = [fld.name for fld in Report._meta.fields]

    fields.append("id")
    try:
        fields = list(set(fields))
        nb_record_filtered = Report.filter(where).count()
        reports = Report.filter(where).values(*fields).order_by(*sort)
        reports = reports[(offset - 1) * limit : limit * offset]
        len(reports)  # Force django to evaluate query now
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

    _format_report_response(reports)
    return list(reports), nb_record_filtered


def _generate_request_filters(filters, user):
    """ Generates filters base on filter query string
    """
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
    where = [Q()]
    if "where" in filters and filters["where"]:
        keys = set(k for k in filters["where"])
        if "in" in keys:
            for i in filters["where"]["in"]:
                for key, val in i.iteritems():
                    field = reduce(
                        lambda a, kv: a.replace(*kv), REPORT_FILTER_MAPPING, key
                    )
                    where.append(reduce(operator.or_, [Q(**{field: i}) for i in val]))
        if "like" in keys:
            like = []
            for i in filters["where"]["like"]:
                for key, val in i.iteritems():
                    field = reduce(
                        lambda a, kv: a.replace(*kv), REPORT_FILTER_MAPPING, key
                    )
                    field = field + "__icontains"
                    like.append(Q(**{field: val[0]}))
            if like:
                where.append(reduce(operator.or_, like))
    else:
        # All except closed
        where.append(~Q(status="Archived"))

    # Force allowed category (only if different from all)
    allowed = list(
        AbusePermission.filter(user=user.id).values_list("category", flat=True)
    )
    if set(allowed) != ALL_CATEGORIES:
        where.append(Q(category__in=allowed))

    where = reduce(operator.and_, where)
    return where


def _format_report_response(reports):
    """ Convert datetime object and add flat foreign key
    """
    for rep in reports:

        # Flat foreign models
        if rep.get("defendant"):
            defendant = Defendant.get(id=rep["defendant"])
            rep["defendant"] = model_to_dict(defendant, exclude=["tags"])
            rep["defendant"]["email"] = defendant.details.email
        if rep.get("service"):
            rep["service"] = model_to_dict(Service.get(id=rep["service"]))
        if rep.get("provider"):
            provider = ProvidersController.show(rep["provider"])
            provider.pop("tags", None)
            rep["provider"] = provider
        if rep.get("tags"):
            tags = Report.get(id=rep["id"]).tags.all()
            rep["tags"] = [model_to_dict(tag) for tag in tags]


def _add_search_filters(filters, query):
    """
        Add Search Service response to filters
    """
    search_query = query

    # Try to parse IP/CIDR search
    if IP_CIDR_RE.match(query):
        try:
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
                if key == "id" and values:
                    reports.extend(values)
                    filters["where"]["in"].remove({key: values})
            filters["where"]["in"].append({"id": list(set(reports))})
    else:
        filters["where"]["in"] = [{"id": reports}]


def show(report_id):
    """
        Get report
    """
    try:
        report = Report.filter(id=report_id).values(*REPORT_FIELDS)[0]
    except (IndexError, ValueError):
        raise NotFound("Report not found")

    # Add related infos
    if report.get("service"):
        report["service"] = model_to_dict(Service.get(id=report["service"]))
    if report.get("defendant"):
        report["defendant"] = DefendantsController.show(report["defendant"])
    if report.get("provider"):
        report["provider"] = ProvidersController.show(report["provider"])

    tags = Report.get(id=report["id"]).tags.all()
    report["tags"] = [model_to_dict(tag) for tag in tags]

    return report


def update(report_id, body, user):
    """ Update a report
    """
    allowed, body = _precheck_user_fields_update_authorizations(user, body)
    if not allowed:
        raise Forbidden("You are not allowed to edit any fields")

    try:
        report = Report.get(id=int(report_id))
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Report not found")

    # Update status
    if body.get("status") != report.status:
        _update_status(body, report, user)
        return show(report_id)

    # Update defendant
    if "defendant" in body:
        # Means unset defendant for report
        if body["defendant"] is None and report.defendant:
            report.reportItemRelatedReport.all().delete()
            report.service = None
            report.save()
            body["ticket"] = None
            body["status"] = "New"
        elif (
            report.defendant
            and body.get("defendant")
            and body["defendant"].get("customerId") != report.defendant.customerId
        ):
            update_defendant(body, report)
    try:
        body["defendant"] = body["defendant"]["id"]
    except (AttributeError, KeyError, TypeError, ValueError):
        pass

    # Update other fields
    try:
        valid_fields = ["defendant", "category", "ticket"]
        body = {k: v for k, v in body.iteritems() if k in valid_fields}
        Report.filter(id=report.id).update(**body)
        report = Report.get(id=int(report_id))
        if report.ticket:
            report.ticket.set_higher_priority()
    except (
        KeyError,
        FieldDoesNotExist,
        FieldError,
        IntegrityError,
        TypeError,
        ValueError,
    ) as ex:
        raise BadRequest(str(ex.message))

    return show(report_id)


def _update_status(body, report, user):
    """
        Update report status
    """
    if body["status"].lower() not in REPORT_STATUS:
        raise BadRequest("Invalid status")

    # Detach report if requested status is "New"
    # If status in ['attached'], try to attach to existing ticket
    #
    if body["status"].lower() == "new":
        if (
            report.ticket and report.ticket.reportTicket.count() == 1
        ):  # Close corresponding ticket
            ticket = Ticket.get(id=report.ticket.id)
            ticket.status = "Closed"
            ticket.save()
        body["ticket"] = None
        report.status = "New"
        report.save()
    elif body["status"].lower() == "attached" and not report.ticket:
        return TicketsController.create(body, user)
    elif body["status"].lower() == "archived":
        report.status = "Archived"
        report.save()

    return body


def update_defendant(body, report):
    """ Update report defendant
    """
    # Convert defendant object in body to Defendant db object
    try:
        defendant = DefendantsController.get_or_create(
            customer_id=body["defendant"]["customerId"]
        )
        body["defendant"] = defendant.id
        if not defendant:
            raise BadRequest("Defendant not found")
    except KeyError:
        raise BadRequest("Missing customerId in defendant object")

    # If this report is attached to a ticket and the defendant is different
    # Try to attach ticket to an existing
    # else, unset ticket and set status to "New"
    #
    if (
        report.ticket
        and report.ticket.defendant
        and (report.ticket.defendant != defendant)
    ):
        # If related ticket has just this report attached, close this ticket
        if report.ticket.reportTicket.count() == 1 and report.ticket.reportTicket.all()[
            0
        ].id == int(report.id):
            try:
                ticket = Ticket.get(id=report.ticket.id)
                ticket.status = "Closed"
                ticket.save()
            except ObjectDoesNotExist:
                pass
        if all((report.category, defendant, report.service)):
            try:
                ticket = Ticket.get(
                    ~Q(status="Closed"),
                    category=report.category.pk,
                    defendant=body["defendant"],
                    service=report.service,
                    update=True,
                )
                report.ticket = ticket
                body["status"] = "Attached"
            except ObjectDoesNotExist:
                report.ticket = None
                body["status"] = "New"
        else:
            report.ticket = None
            body["status"] = "New"

        report.save()
        body.pop("ticket", None)

    return body


def destroy(report_id):
    """ Archived a report
    """
    report = Report.filter(id=report_id)
    if not report:
        raise NotFound("Report not found")
    report.update(status="Archived")
    return {"message": "Report successfully archived"}


def validate(report_id, body, user):
    """
        Parse now validated "ToValidate" `abuse.models.Report`
    """
    try:
        report = Report.get(id=int(report_id))
        if report.status.lower() != "tovalidate":
            raise BadRequest("Report is not in ToValidate state")
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Report not found")

    function = None
    params = {
        "report_id": report.id,
        "user_id": user.id,
        "domain_to_request": None,
        "timeout": 3600,
    }

    if report.defendant and report.service:
        function = "report.validate_with_defendant"
        params.pop("user_id", None)
    else:
        if body.get("domainToRequest"):
            search = re.search(Parser.domain_re, body["domainToRequest"])
            if not search:
                raise BadRequest("Not a valid domain name")
            function = "report.cdn_request"
            params["domain_to_request"] = search.group()
        else:
            function = "report.validate_without_defendant"

    report.status = "Attached"
    report.save()

    params = {k: v for k, v in params.iteritems() if v}
    enqueue(function, queue="email", **params)

    return {"message": "Report successfully validated"}


def get_raw(report_id):
    """ Get raw email of report
    """
    report = None
    try:
        report = Report.get(id=report_id)
        if not report.filename:
            return {"raw": report.body}

        raw = None
        try:
            raw = StorageService.read(report.filename)
        except StorageServiceException:
            pass

        if not raw:
            raise NotFound("Raw not found")

        return {"raw": raw.decode("utf-8")}
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Report not found")


def get_dehtmlified(report_id):
    """ Get raw email of report
    """
    try:
        report = Report.get(id=report_id)
        html = html2text.HTML2Text()
        html.body_width = 0
        body = html.handle(report.body.replace("\r\n", "<br/>"))
        body = re.sub(r"^(\s*\n){2,}", "\n", body, flags=re.MULTILINE)
        return {"dehtmlify": body}
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Report not found")


def get_all_attachments(**kwargs):
    """ Get attached documents for a report
    """
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

    try:
        report = Report.get(id=kwargs["report"])
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Report not found")

    try:
        nb_record_filtered = report.attachments.count()
        attached = report.attachments.all().values(*REPORT_ATTACHMENT_FIELDS)
        attached = attached[(offset - 1) * limit : limit * offset]
        len(attached)  # Force django to evaluate query now
    except (
        AttributeError,
        KeyError,
        FieldError,
        SyntaxError,
        TypeError,
        ValueError,
    ) as ex:
        raise BadRequest(str(ex.message))

    return list(attached), nb_record_filtered


def get_attachment(report_id, attachment_id):
    """ Get attachment
    """
    try:
        report = Report.get(id=report_id)
        attachment = report.attachments.get(id=attachment_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Report or attachment not found")

    resp = None
    try:
        raw = StorageService.read(attachment.filename)
        resp = {
            "raw": b64encode(raw),
            "filetype": str(attachment.filetype),
            "filename": attachment.name.encode("utf-8"),
        }
    except StorageServiceException:
        pass

    if not resp:
        raise NotFound("Raw attachment not found")

    return resp


@transaction.atomic
def bulk_add(body, user, method):
    """ Update multiple reports
    """
    if not body.get("reports") or not body.get("properties"):
        raise BadRequest("Missing reports or properties in body")

    try:
        reports = Report.filter(id__in=list(body["reports"]))
    except (TypeError, ValueError):
        raise BadRequest("Invalid report(s) id")

    for report in reports:
        MiscController.check_perms(method=method, user=user, report=report.id)

    if (
        body["properties"].get("status")
        and body["properties"]["status"].lower() not in REPORT_STATUS
    ):
        raise BadRequest("Status not supported")

    # Update tags
    if "tags" in body["properties"] and isinstance(body["properties"]["tags"], list):
        for report in reports:
            for tag in body["properties"]["tags"]:
                add_tag(report.id, tag)

    valid_fields = ["category", "status", "ticket"]
    properties = {k: v for k, v in body["properties"].iteritems() if k in valid_fields}

    # Update general fields
    for report in reports:
        update(report.id, properties, user)

    return {"message": "Report(s) successfully updated"}


@transaction.atomic
def bulk_delete(body, user, method):
    """ Delete infos from multiple tickets
    """
    if not body.get("reports") or not body.get("properties"):
        raise BadRequest("Missing reports or properties in body")

    try:
        reports = Report.filter(id__in=list(body["reports"]))
    except (TypeError, ValueError):
        raise BadRequest("Invalid report(s) id")

    for report in reports:
        MiscController.check_perms(method=method, user=user, ticket=report.id)

    # Update tags
    try:
        if "tags" in body["properties"] and isinstance(
            body["properties"]["tags"], list
        ):
            for report in reports:
                for tag in body["properties"]["tags"]:
                    remove_tag(report.id, tag["id"])
    except (KeyError, TypeError, ValueError):
        raise BadRequest("Invalid or missing tag(s) id")

    return {"message": "Report(s) successfully updated"}


def add_tag(report_id, body):
    """ Add report tag
    """
    try:
        tag = Tag.get(**body)
        report = Report.get(id=report_id)

        if report.__class__.__name__ != tag.tagType:
            raise BadRequest("Invalid tag for report")

        report.tags.add(tag)
        report.save()
    except MultipleObjectsReturned:
        raise BadRequest("Please use tag id")
    except (KeyError, FieldError, IntegrityError, ObjectDoesNotExist, ValueError):
        raise NotFound("Report or tag not found")
    return {"message": "Tag successfully added"}


def remove_tag(report_id, tag_id):
    """ Remove report tag
    """
    try:
        tag = Tag.get(id=tag_id)
        report = Report.get(id=report_id)

        if report.__class__.__name__ != tag.tagType:
            raise BadRequest("Invalid tag for report")

        report.tags.remove(tag)
        report.save()

    except (ObjectDoesNotExist, FieldError, IntegrityError, ValueError):
        raise NotFound("Report or tag not found")
    return {"message": "Tag successfully removed"}


def get_items_screenshot(**kwargs):
    """ For all URL items, get all screenshots available on Antiphishing Tester service
    """
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

    only_taken = False
    if kwargs.get("only_taken"):
        only_taken = kwargs["only_taken"]

    try:
        report = Report.get(id=kwargs["report"])
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Report not found")

    items = report.reportItemRelatedReport.filter(itemType="URL").values_list(
        "id", flat=True
    )[(offset - 1) * limit : limit * offset]
    items = list(set(items))

    queue = Queue()
    threads = []

    for item in items:
        thread = Thread(
            target=_get_url_screenshot, args=(item, report.id, queue, only_taken)
        )
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    results = [queue.get() for _ in xrange(len(items))]

    for res in results:
        if not res:
            raise InternalServerError("Error while loading screenshots")
    return results


def _get_url_screenshot(item_id, report_id, queue, only_taken=False):
    """ Get screenshots for given url
    """
    try:
        resp = ReportItemsController.get_screenshot(item_id, report_id)
    except (NotFound, BadRequest, InternalServerError):
        resp = None

    queue.put(resp)


def parse_screenshot_feedback(report_id, body, user):
    """ Get operator result after manual check
    """
    try:
        report = Report.get(id=report_id)
        if report.status != "PhishToCheck":
            message = (
                "Report status is now %s, maybe already "
                "checked by someone else" % (report.status)
            )
            raise BadRequest(message)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Report not found")

    if not body:
        raise BadRequest("Invalid or missing body")

    # Parse result and update Phishing Service
    try:
        for item in body:
            enqueue(
                "phishing.feedback_to_phishing_service",
                screenshot_id=item.get("screenshotId"),
                feedback=item.get("feedback"),
            )
    except (AttributeError, KeyError, TypeError):
        raise BadRequest("Missing key in item body")

    result = {item.get("screenshotId"): item.get("feedback") for item in body}

    # Delete all non-phishing items
    for item, res in result.iteritems():
        if not res:
            ReportItem.filter(rawItem=item, report=report).delete()

    # If no more items, notification to provider and closing ticket
    report.status = "New"
    report.save()
    if not any(result.values()):
        enqueue("phishing.close_because_all_down", report=report.id, denied_by=user.id)
        return {"message": "Report successfully archived and mail sent to provider"}

    # Else create/attach report to ticket + block_url + mail to defendant + email to provider
    enqueue("ticket.create_ticket_from_phishtocheck", report=report.id, user=user.id)
    return {"message": "Report will be attached to ticket in few seconds"}


def _precheck_user_fields_update_authorizations(user, body):
    """
       Check if user's update paramaters are allowed
    """
    authorizations = user.operator.role.modelsAuthorizations
    if authorizations.get("report") and authorizations["report"].get("fields"):
        body = {
            k: v for k, v in body.iteritems() if k in authorizations["report"]["fields"]
        }
        if not body:
            return False, body
        return True, body
    return False, body
