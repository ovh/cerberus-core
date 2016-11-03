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
from werkzeug.exceptions import BadRequest

from api.controllers import (CommentsController, TicketsController,
                             PresetsController, ReportItemsController,
                             TemplatesController)
from decorators import jsonify, perm_required

ticket_views = Blueprint('ticket_views', __name__)


@ticket_views.route('/api/tickets', methods=['GET'])
def get_tickets():
    """ Get all abuse tickets

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    resp, _ = TicketsController.index(filters=request.args.get('filters'), user=g.user)
    return resp


@ticket_views.route('/api/my-tickets', methods=['GET'])
def get_user_tickets():
    """ Get abuse tickets for logged g.user

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    resp, _ = TicketsController.index(
        filters=request.args.get('filters'),
        treated_by=g.user.id,
        user=g.user
    )
    return resp


@ticket_views.route('/api/tickets/todo', methods=['GET'])
def get_todo_tickets():
    """ Get all abuse todo tickets
    """
    return TicketsController.get_todo_tickets(filters=request.args.get('filters'), user=g.user)


@ticket_views.route('/api/tickets/<ticket>', methods=['GET'])
@perm_required
def get_ticket(ticket=None):
    """ Get a given ticket
    """
    return TicketsController.show(ticket, g.user)


@ticket_views.route('/api/tickets/<ticket>/items', methods=['GET'])
@perm_required
def get_ticket_items(ticket=None):
    """ Get all items for a given ticket

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    return ReportItemsController.get_items_ticket(
        ticket=ticket,
        filters=request.args.get('filters')
    )


@ticket_views.route('/api/tickets/<ticket>/items/<item>', methods=['PUT', 'DELETE'])
@jsonify
@perm_required
def update_ticket_item(ticket=None, item=None):
    """ Delete an item
    """
    if request.method == 'PUT':
        body = request.get_json()
        code, resp = ReportItemsController.update(item, body, g.user)
    else:
        code, resp = ReportItemsController.delete_from_ticket(item, ticket)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/items/<item>/unblock', methods=['POST'])
@jsonify
@perm_required
def unblock_ticket_item(ticket=None, item=None):
    """ Unblock an item
    """
    code, resp = ReportItemsController.unblock_item(item_id=item, ticket_id=ticket)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/proof', methods=['GET', 'POST'])
@perm_required
def get_ticket_proof(ticket=None):
    """ Get all proof for a given ticket
    """
    if request.method == 'GET':
        return TicketsController.get_proof(ticket)
    else:
        body = request.get_json()
        return TicketsController.add_proof(ticket, body, g.user)


@ticket_views.route('/api/tickets/bulk', methods=['PUT', 'DELETE'])
def bulk_add_tickets():
    """ Bulk add on tickets
    """
    body = request.get_json()
    if request.method == 'PUT':
        return TicketsController.bulk_update(body, g.user, request.method)
    else:
        return TicketsController.bulk_delete(body, g.user, request.method)


@ticket_views.route('/api/tickets/<ticket>/proof/<proof>', methods=['PUT', 'DELETE'])
@perm_required
def update_ticket_proof(ticket=None, proof=None):
    """ Update ticket proof
    """
    if request.method == 'PUT':
        body = request.get_json()
        return TicketsController.update_proof(ticket, proof, body, g.user)
    else:
        return TicketsController.delete_proof(ticket, proof, g.user)


@ticket_views.route('/api/tickets', methods=['POST'])
@perm_required
def create_ticket():
    """ Post a new ticket
    """
    body = request.get_json()
    return TicketsController.create(body, g.user)


@ticket_views.route('/api/tickets/<ticket>', methods=['PUT'])
@perm_required
def update_ticket(ticket=None):
    """ Update an existing ticket
    """
    body = request.get_json()
    return TicketsController.update(ticket, body, g.user)


@ticket_views.route('/api/tickets/<ticket>/snoozeDuration', methods=['PATCH'])
@perm_required
def update_ticket_snooze(ticket=None):
    """ Update ticket snoozeDuration
    """
    body = request.get_json()
    return TicketsController.update_snooze_duration(ticket, body, g.user)


@ticket_views.route('/api/tickets/<ticket>/pauseDuration', methods=['PATCH'])
@perm_required
def update_ticket_pause(ticket=None):
    """ Update ticket pauseDuration
    """
    body = request.get_json()
    return TicketsController.update_pause_duration(ticket, body, g.user)


@ticket_views.route('/api/tickets/<ticket>/defendant', methods=['PUT'])
@perm_required
def update_ticket_defendant(ticket=None):
    """ Update ticket defendant
    """
    body = request.get_json()
    return TicketsController.update(ticket, body, g.user)


@ticket_views.route('/api/tickets/<ticket>/emails', methods=['GET'])
@perm_required
def get_mails(ticket=None):
    """ Get all emails sent and received for this ticket
    """
    return TicketsController.get_emails(ticket)


@ticket_views.route('/api/tickets/<ticket>/status/<status>', methods=['PUT'])
@perm_required
def update_status(ticket=None, status=None):
    """ Update ticket status
    """
    if status and status.lower() == 'closed':
        raise BadRequest('To close ticket, please use Interact')

    body = request.get_json()
    return TicketsController.update_status(ticket, status, body, g.user)


@ticket_views.route('/api/tickets/<ticket>/templates/<template>', methods=['GET'])
@jsonify
@perm_required
def get_ticket_prefetched_template(ticket=None, template=None):
    """ Get a template prefetched with ticket infos
    """
    code, resp = TemplatesController.get_prefetch_template(ticket, template)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/presets/<preset>', methods=['GET'])
@jsonify
@perm_required
def get_ticket_prefetched_preset(ticket=None, preset=None):
    """ Get a template prefetched with ticket infos
    """
    code, resp = PresetsController.get_prefetch_preset(g.user, ticket, preset)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/tags', methods=['POST'])
@perm_required
def add_ticket_tag(ticket=None):
    """ Add tag to ticket
    """
    body = request.get_json()
    return TicketsController.add_tag(ticket, body, g.user)


@ticket_views.route('/api/tickets/<ticket>/tags/<tag>', methods=['DELETE'])
@perm_required
def delete_ticket_tag(ticket=None, tag=None):
    """ Remove ticket tag
    """
    return TicketsController.remove_tag(ticket, tag, g.user)


@ticket_views.route('/api/tickets/<ticket>/interact', methods=['POST'])
@perm_required
def interact(ticket=None):
    """ Magic endpoint to save operator's time
    """
    body = request.get_json()
    return TicketsController.interact(ticket, body, g.user)


@ticket_views.route('/api/tickets/<ticket>/actions/list', methods=['GET'])
@perm_required
def get_actions(ticket=None):
    """
        List all available actions
    """
    return TicketsController.get_actions_list(ticket, g.user)


@ticket_views.route('/api/tickets/<ticket>/jobs', methods=['GET'])
@perm_required
def get_jobs(ticket=None):
    """
        Get actions status
    """
    return TicketsController.get_jobs_status(ticket)


@ticket_views.route('/api/tickets/<ticket>/jobs', methods=['POST'])
@perm_required
def schedule_job(ticket=None):
    """
        Schedule action
    """
    body = request.get_json()
    if not body.get('action') or not body.get('delay'):
        return BadRequest('Missing action or delay in body')
    return TicketsController.schedule_asynchronous_job(
        ticket,
        body.get('action'),
        g.user,
        body.get('delay')
    )


@ticket_views.route('/api/tickets/<ticket>/jobs/<job>', methods=['DELETE'])
@perm_required
def cancel_job(ticket=None, job=None):
    """
        Cancel action
    """
    return TicketsController.cancel_asynchronous_job(ticket, job, g.user)


@ticket_views.route('/api/tickets/<ticket>/comments', methods=['POST'])
@jsonify
@perm_required
def add_comment(ticket=None):
    """ Add comment to ticket
    """
    body = request.get_json()
    code, resp = CommentsController.create(body, ticket_id=ticket, user_id=g.user.id)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/comments/<comment>', methods=['PUT', 'DELETE'])
@jsonify
@perm_required
def update_or_delete_comment(ticket=None, comment=None):
    """ Update or delete ticket comments
    """
    if request.method == 'PUT':
        body = request.get_json()
        code, resp = CommentsController.update(body, comment_id=comment, ticket_id=ticket, user_id=g.user.id)
    else:
        code, resp = CommentsController.delete(comment_id=comment, ticket_id=ticket, user_id=g.user.id)

    return code, resp


@ticket_views.route('/api/tickets/<ticket>/providers', methods=['GET'])
@perm_required
def get_providers(ticket=None):
    """ Get ticket's providers
    """
    return TicketsController.get_providers(ticket)


@ticket_views.route('/api/tickets/<ticket>/timeline', methods=['GET'])
@perm_required
def get_timeline(ticket=None):
    """ Get ticket's timeline
    """
    return TicketsController.get_timeline(ticket, filters=request.args.get('filters'))


@ticket_views.route('/api/tickets/<ticket>/attachments/<attachment>', methods=['GET'])
@perm_required
def get_ticket_attachment(ticket=None, attachment=None):
    """ Get `abuse.models.Ticket`'s `abuse.models.AttachedDocument`
    """
    resp = TicketsController.get_attachment(ticket, attachment)
    bytes_io = BytesIO(resp['raw'])
    return send_file(
        bytes_io,
        attachment_filename=resp['filename'],
        mimetype=resp['filetype'],
        as_attachment=True
    )
