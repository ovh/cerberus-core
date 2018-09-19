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
    Ticket views for Cerberus protected API.
"""

from io import BytesIO

from flask import Blueprint, g, request, send_file
from voluptuous import Any, Optional
from werkzeug.exceptions import BadRequest

from ..decorators import perm_required, validate_body
from ..controllers import interact as InteractController
from ..controllers import presets as PresetsController
from ..controllers import tickets as TicketsController
from ..controllers import reportitems as ReportItemsController
from ..controllers import templates as TemplatesController
from ..controllers import comments as CommentsController

ticket_views = Blueprint("ticket_views", __name__, url_prefix="/tickets")


@ticket_views.route("", methods=["GET"])
def get_tickets():
    """ Get all abuse tickets

    """
    resp, _ = TicketsController.get_tickets(
        filters=request.args.get("filters"), user=g.user
    )
    return resp


@ticket_views.route("/todo", methods=["GET"])
def get_todo_tickets():
    """ Get all abuse todo tickets
    """
    return TicketsController.get_todo_tickets(
        filters=request.args.get("filters"), user=g.user
    )


@ticket_views.route("/<ticket>", methods=["GET"])
@perm_required
def get_ticket(ticket=None):
    """ Get a given ticket
    """
    return TicketsController.show(ticket, g.user)


@ticket_views.route("/<ticket>/items", methods=["GET"])
@perm_required
def get_ticket_items(ticket=None):
    """ Get all items for a given ticket
    """
    return ReportItemsController.get_items_ticket(
        ticket=ticket, filters=request.args.get("filters")
    )


@ticket_views.route("/<ticket>/items/toproof", methods=["POST"])
@perm_required
def add_items_to_proof(ticket=None):
    """
        Add all `abuse.models.ReportItems` to
        `abuse.models.Ticket`'s `abuse.models.Proof`
    """
    return TicketsController.add_items_to_proof(ticket_id=ticket, user=g.user)


@ticket_views.route("/<ticket>/items/<item>", methods=["PUT", "DELETE"])
@perm_required
def update_ticket_item(ticket=None, item=None):
    """ Delete an item
    """
    if request.method == "PUT":
        body = request.get_json()
        return ReportItemsController.update(item, body, g.user)
    return ReportItemsController.delete_from_ticket(item, ticket)


@ticket_views.route("/<ticket>/items/<item>/unblock", methods=["POST"])
@perm_required
def unblock_ticket_item(ticket=None, item=None):
    """ Unblock an item
    """
    return ReportItemsController.unblock_item(item_id=item, ticket_id=ticket)


@ticket_views.route("/<ticket>/proof", methods=["GET", "POST"])
@perm_required
def get_ticket_proof(ticket=None):
    """ Get all proof for a given ticket
    """
    if request.method == "GET":
        return TicketsController.get_proof(ticket)
    body = request.get_json()
    return TicketsController.add_proof(ticket, body, g.user)


@ticket_views.route("/bulk", methods=["PUT", "DELETE"])
def bulk_add_tickets():
    """ Bulk add on tickets
    """
    body = request.get_json()
    if request.method == "PUT":
        return TicketsController.bulk_update(body, g.user, request.method)
    return TicketsController.bulk_delete(body, g.user, request.method)


@ticket_views.route("/<ticket>/proof/<proof>", methods=["PUT", "DELETE"])
@perm_required
def update_ticket_proof(ticket=None, proof=None):
    """ Update ticket proof
    """
    if request.method == "PUT":
        body = request.get_json()
        return TicketsController.update_proof(ticket, proof, body, g.user)
    return TicketsController.delete_proof(ticket, proof, g.user)


@ticket_views.route("/<ticket>", methods=["PUT"])
@perm_required
def update_ticket(ticket=None):
    """ Update an existing ticket
    """
    body = request.get_json()
    return TicketsController.update(ticket, body, g.user)


@ticket_views.route("/<ticket>/snoozeDuration", methods=["PATCH"])
@perm_required
def update_ticket_snooze(ticket=None):
    """ Update ticket snoozeDuration
    """
    body = request.get_json()
    return TicketsController.update_snooze_duration(ticket, body, g.user)


@ticket_views.route("/<ticket>/pauseDuration", methods=["PATCH"])
@perm_required
def update_ticket_pause(ticket=None):
    """ Update ticket pauseDuration
    """
    body = request.get_json()
    return TicketsController.update_pause_duration(ticket, body, g.user)


@ticket_views.route("/<ticket>/defendant", methods=["PUT"])
@perm_required
def update_ticket_defendant(ticket=None):
    """ Update ticket defendant
    """
    body = request.get_json()
    return TicketsController.update(ticket, body, g.user)


@ticket_views.route("/<ticket>/emails", methods=["GET"])
@perm_required
def get_mails(ticket=None):
    """ Get all emails sent and received for this ticket
    """
    return TicketsController.get_emails(ticket)


@ticket_views.route("/<ticket>/status/<status>", methods=["PUT"])
@perm_required
def update_status(ticket=None, status=None):
    """ Update ticket status
    """
    if status and status.lower() == "closed":
        raise BadRequest("To close ticket, please use Interact")

    body = request.get_json()
    return TicketsController.update_status(ticket, status, body, g.user)


@ticket_views.route("/<ticket>/templates/<template>", methods=["GET"])
@perm_required
def get_ticket_prefetched_template(ticket=None, template=None):
    """ Get a template prefetched with ticket infos
    """
    return TemplatesController.get_prefetch_template(ticket, template)


@ticket_views.route("/<ticket>/presets/<preset>", methods=["GET"])
@perm_required
def get_ticket_prefetched_preset(ticket=None, preset=None):
    """ Get a template prefetched with ticket infos
    """
    return PresetsController.get_prefetch_preset(g.user, ticket, preset)


@ticket_views.route("/<ticket>/tags", methods=["POST"])
@perm_required
def add_ticket_tag(ticket=None):
    """ Add tag to ticket
    """
    body = request.get_json()
    return TicketsController.add_tag(ticket, body, g.user)


@ticket_views.route("/<ticket>/tags/<tag>", methods=["DELETE"])
@perm_required
def delete_ticket_tag(ticket=None, tag=None):
    """ Remove ticket tag
    """
    return TicketsController.remove_tag(ticket, tag, g.user)


@ticket_views.route("/<ticket>/interact", methods=["POST"])
@perm_required
@validate_body(
    {
        "action": {
            Optional("id"): int,
            "codename": Any(str, unicode),
            "params": {
                Optional("ip"): Any(str, unicode),
                Optional("action"): int,
                Optional("snoozeDuration"): int,
                Optional("pauseDuration"): int,
                Optional("resolution"): int,
            },
        },
        Optional("emails"): [
            {
                "category": Any(str, unicode),
                "to": [Any(str, unicode)],
                "subject": Any(str, unicode),
                "body": Any(str, unicode),
                Optional("attachments"): [
                    {
                        Optional("name"): Any(str, unicode),
                        Optional("content"): Any(str, unicode),
                        Optional("id"): int,
                        Optional("filename"): Any(str, unicode),
                        "filetype": Any(str, unicode),
                    }
                ],
                Optional("attachEmailThread"): bool,
            }
        ],
    }
)
def interact(ticket=None):
    """ Magic endpoint to save operator's time
    """
    body = request.get_json()
    return InteractController.interact(ticket, body, g.user)


@ticket_views.route("/<ticket>/actions/list", methods=["GET"])
@perm_required
def get_actions(ticket=None):
    """
        List all available actions
    """
    return TicketsController.get_actions_list(ticket, g.user)


@ticket_views.route("/<ticket>/jobs/<job>", methods=["DELETE"])
@perm_required
def cancel_job(ticket=None, job=None):
    """
        Cancel action
    """
    return TicketsController.cancel_asynchronous_job(ticket, job, g.user)


@ticket_views.route("/<ticket>/comments", methods=["POST"])
@perm_required
def add_comment(ticket=None):
    """ Add comment to ticket
    """
    body = request.get_json()
    return CommentsController.create(body, ticket_id=ticket, user_id=g.user.id)


@ticket_views.route("/<ticket>/comments/<comment>", methods=["PUT", "DELETE"])
@perm_required
def update_or_delete_comment(ticket=None, comment=None):
    """ Update or delete ticket comments
    """
    if request.method == "PUT":
        body = request.get_json()
        return CommentsController.update(
            body, comment_id=comment, ticket_id=ticket, user_id=g.user.id
        )
    return CommentsController.delete(
        comment_id=comment, ticket_id=ticket, user_id=g.user.id
    )


@ticket_views.route("/<ticket>/providers", methods=["GET"])
@perm_required
def get_providers(ticket=None):
    """ Get ticket's providers
    """
    return TicketsController.get_providers(ticket)


@ticket_views.route("/<ticket>/timeline", methods=["GET"])
@perm_required
def get_timeline(ticket=None):
    """ Get ticket's timeline
    """
    return TicketsController.get_timeline(ticket, filters=request.args.get("filters"))


@ticket_views.route("/<ticket>/attachments", methods=["GET"])
@perm_required
def get_ticket_attachments(ticket=None):
    """ Get all `abuse.models.Ticket`'s `abuse.models.AttachedDocument`
    """
    return TicketsController.get_ticket_attachments(ticket)


@ticket_views.route("/<ticket>/attachments/<attachment>", methods=["GET"])
@perm_required
def get_ticket_attachment(ticket=None, attachment=None):
    """ Get `abuse.models.Ticket`'s `abuse.models.AttachedDocument`
    """
    resp = TicketsController.get_attachment(ticket, attachment)
    bytes_io = BytesIO(resp["raw"])
    return send_file(
        bytes_io,
        attachment_filename=resp["filename"],
        mimetype=resp["filetype"],
        as_attachment=True,
    )


@ticket_views.route("/<ticket>/star", methods=["POST", "DELETE"])
@perm_required
def ticket_star_management(ticket=None):
    """
        Star/Unstar given `abuse.models.Ticket` for given `abuse.models.User`

    :status 200: when category is successfully created
    :status 400: when parameters are missing or invalid
    :status 404: when ticket is not found
    """
    return TicketsController.star_ticket_management(
        ticket, g.user, method=request.method
    )
