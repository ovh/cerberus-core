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

from flask import Blueprint, g, request

from api.controllers import (CommentsController, TicketsController,
                             PresetsController, ReportItemsController,
                             TemplatesController)
from decorators import jsonify, perm_required

ticket_views = Blueprint('ticket_views', __name__)


@ticket_views.route('/api/tickets', methods=['GET'])
@jsonify
def get_tickets():
    """ Get all abuse tickets

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    if 'filters' in request.args:
        code, resp, nb_tickets = TicketsController.index(filters=request.args['filters'], user=g.user)
    else:
        code, resp, nb_tickets = TicketsController.index(user=g.user)
    return code, resp


@ticket_views.route('/api/my-tickets', methods=['GET'])
@jsonify
def get_user_tickets():
    """ Get abuse tickets for logged g.user

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    if 'filters' in request.args:
        code, resp, nb_tickets = TicketsController.index(filters=request.args['filters'], treated_by=g.user.id, user=g.user)
    else:
        code, resp, nb_tickets = TicketsController.index(treated_by=g.user.id, user=g.user)
    return code, resp


@ticket_views.route('/api/tickets/todo', methods=['GET'])
@jsonify
def get_todo_tickets():
    """ Get all abuse todo tickets
    """
    code, resp = TicketsController.get_todo_tickets(filters=request.args.get('filters'), user=g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>', methods=['GET'])
@jsonify
@perm_required
def get_ticket(ticket=None):
    """ Get a given ticket
    """
    code, resp = TicketsController.show(ticket, g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/items', methods=['GET'])
@jsonify
@perm_required
def get_ticket_items(ticket=None):
    """ Get all items for a given ticket

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    if 'filters' in request.args:
        code, resp = ReportItemsController.get_items_ticket(ticket=ticket, filters=request.args['filters'])
    else:
        code, resp = ReportItemsController.get_items_ticket(ticket=ticket)
    return code, resp


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


@ticket_views.route('/api/tickets/<ticket>/proof', methods=['GET', 'POST'])
@jsonify
@perm_required
def get_ticket_proof(ticket=None):
    """ Get all proof for a given ticket
    """
    if request.method == 'GET':
        code, resp = TicketsController.get_proof(ticket)
    else:
        body = request.get_json()
        code, resp = TicketsController.add_proof(ticket, body, g.user)
    return code, resp


@ticket_views.route('/api/tickets/bulk', methods=['PUT', 'DELETE'])
@jsonify
def bulk_add_tickets():
    """ Bulk add on tickets
    """
    body = request.get_json()
    if request.method == 'PUT':
        code, resp = TicketsController.bulk_update(body, g.user, request.method)
    else:
        code, resp = TicketsController.bulk_delete(body, g.user, request.method)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/proof/<proof>', methods=['PUT', 'DELETE'])
@jsonify
@perm_required
def update_ticket_proof(ticket=None, proof=None):
    """ Update ticket proof
    """
    if request.method == 'PUT':
        body = request.get_json()
        code, resp = TicketsController.update_proof(ticket, proof, body, g.user)
    else:
        code, resp = TicketsController.delete_proof(ticket, proof, g.user)
    return code, resp


@ticket_views.route('/api/tickets', methods=['POST'])
@jsonify
@perm_required
def create_ticket():
    """ Post a new ticket
    """
    body = request.get_json()
    code, resp = TicketsController.create(body, g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>', methods=['PUT'])
@jsonify
@perm_required
def update_ticket(ticket=None):
    """ Update an existing ticket
    """
    body = request.get_json()
    code, resp = TicketsController.update(ticket, body, g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/snoozeDuration', methods=['PATCH'])
@jsonify
@perm_required
def update_ticket_snooze(ticket=None):
    """ Update ticket snoozeDuration
    """
    body = request.get_json()
    code, resp = TicketsController.update_snooze_duration(ticket, body, g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/pauseDuration', methods=['PATCH'])
@jsonify
@perm_required
def update_ticket_pause(ticket=None):
    """ Update ticket pauseDuration
    """
    body = request.get_json()
    code, resp = TicketsController.update_pause_duration(ticket, body, g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/defendant', methods=['PUT'])
@jsonify
@perm_required
def update_ticket_defendant(ticket=None):
    """ Update ticket defendant
    """
    body = request.get_json()
    code, resp = TicketsController.update(ticket, body, g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/emails', methods=['GET'])
@jsonify
@perm_required
def get_mails(ticket=None):
    """ Get all emails sent and received for this ticket
    """
    code, resp = TicketsController.get_emails(ticket)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/status/<status>', methods=['PUT'])
@jsonify
@perm_required
def update_status(ticket=None, status=None):
    """ Update ticket status
    """
    if status and status.lower() == 'closed':
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'To close ticket, please use Interact'}

    body = request.get_json()
    code, resp = TicketsController.update_status(ticket, status, body, g.user)
    return code, resp


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
@jsonify
@perm_required
def add_ticket_tag(ticket=None):
    """ Add tag to ticket
    """
    body = request.get_json()
    code, resp = TicketsController.add_tag(ticket, body, g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/tags/<tag>', methods=['DELETE'])
@jsonify
@perm_required
def delete_ticket_tag(ticket=None, tag=None):
    """ Remove ticket tag
    """
    code, resp = TicketsController.remove_tag(ticket, tag, g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/interact', methods=['POST'])
@jsonify
@perm_required
def interact(ticket=None):
    """ Magic endpoint to save operator's time
    """
    body = request.get_json()
    code, resp = TicketsController.interact(ticket, body, g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/actions/list', methods=['GET'])
@jsonify
@perm_required
def get_actions(ticket=None):
    """
        List all available actions
    """
    code, resp = TicketsController.get_actions_list(ticket, g.user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/jobs', methods=['GET'])
@jsonify
@perm_required
def get_jobs(ticket=None):
    """
        Get actions status
    """
    code, resp = TicketsController.get_jobs_status(ticket)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/jobs', methods=['POST'])
@jsonify
@perm_required
def schedule_job(ticket=None):
    """
        Schedule action
    """
    body = request.get_json()
    if not body.get('action') or not body.get('delay'):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing action or delay in body'}
    code, resp = TicketsController.schedule_asynchronous_job(ticket, body.get('action'), g.user, body.get('delay'))
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/jobs/<job>', methods=['DELETE'])
@jsonify
@perm_required
def cancel_job(ticket=None, job=None):
    """
        Cancel action
    """
    code, resp = TicketsController.cancel_asynchronous_job(ticket, job, g.user)
    return code, resp


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
@jsonify
@perm_required
def get_providers(ticket=None):
    """ Get ticket's providers
    """
    code, resp = TicketsController.get_providers(ticket)
    return code, resp
