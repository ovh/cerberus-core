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

from flask import Blueprint, request

from api.controllers import (CommentsController, GeneralController,
                             PresetsController, ReportItemsController,
                             TemplatesController, TicketsController)
from decorators import (catch_500, json_required, jsonify, perm_required,
                        token_required)

ticket_views = Blueprint('ticket_views', __name__)


@ticket_views.route('/api/tickets', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_tickets():
    """ Get all abuse tickets

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    user = GeneralController.get_user(request)
    if 'filters' in request.args:
        code, resp, nb_tickets = TicketsController.index(filters=request.args['filters'], user=user)
    else:
        code, resp, nb_tickets = TicketsController.index(user=user)
    return code, resp


@ticket_views.route('/api/my-tickets', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_user_tickets():
    """ Get abuse tickets for logged user

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    user = GeneralController.get_user(request)
    if 'filters' in request.args:
        code, resp, nb_tickets = TicketsController.index(filters=request.args['filters'], treated_by=user.id, user=user)
    else:
        code, resp, nb_tickets = TicketsController.index(treated_by=user.id, user=user)
    return code, resp


@ticket_views.route('/api/tickets/todo', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_todo_tickets():
    """ Get all abuse todo tickets
    """
    user = GeneralController.get_user(request)
    code, resp = TicketsController.get_todo_tickets(filters=request.args.get('filters'), user=user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>', methods=['GET'])
@jsonify
@token_required
@perm_required
@catch_500
def get_ticket(ticket=None):
    """ Get a given ticket
    """
    user = GeneralController.get_user(request)
    code, resp = TicketsController.show(ticket, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/items', methods=['GET'])
@jsonify
@token_required
@perm_required
@catch_500
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
@token_required
@perm_required
@catch_500
def update_ticket_item(ticket=None, item=None):
    """ Delete an item
    """
    user = GeneralController.get_user(request)
    if request.method == 'PUT':
        body = request.get_json()
        code, resp = ReportItemsController.update(item, body, user)
    else:
        code, resp = ReportItemsController.delete_from_ticket(item, ticket)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/proof', methods=['GET', 'POST'])
@jsonify
@token_required
@perm_required
@catch_500
def get_ticket_proof(ticket=None):
    """ Get all proof for a given ticket
    """
    if request.method == 'GET':
        code, resp = TicketsController.get_proof(ticket)
    else:
        user = GeneralController.get_user(request)
        body = request.get_json()
        code, resp = TicketsController.add_proof(ticket, body, user)
    return code, resp


@ticket_views.route('/api/tickets/bulk', methods=['PUT', 'DELETE'])
@jsonify
@token_required
@catch_500
def bulk_add_tickets():
    """ Bulk add on tickets
    """
    user = GeneralController.get_user(request)
    body = request.get_json()
    if request.method == 'PUT':
        code, resp = TicketsController.bulk_update(body, user, request.method)
    else:
        code, resp = TicketsController.bulk_delete(body, user, request.method)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/proof/<proof>', methods=['PUT', 'DELETE'])
@jsonify
@token_required
@perm_required
@catch_500
def update_ticket_proof(ticket=None, proof=None):
    """ Update ticket proof
    """
    user = GeneralController.get_user(request)
    if request.method == 'PUT':
        body = request.get_json()
        code, resp = TicketsController.update_proof(ticket, proof, body, user)
    else:
        code, resp = TicketsController.delete_proof(ticket, proof, user)
    return code, resp


@ticket_views.route('/api/tickets', methods=['POST'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def create_ticket():
    """ Post a new ticket
    """
    user = GeneralController.get_user(request)
    body = request.get_json()
    code, resp = TicketsController.create(body, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>', methods=['PUT'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def update_ticket(ticket=None):
    """ Update an existing ticket
    """
    user = GeneralController.get_user(request)
    body = request.get_json()
    code, resp = TicketsController.update(ticket, body, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/snoozeDuration', methods=['PATCH'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def update_ticket_snooze(ticket=None):
    """ Update ticket snoozeDuration
    """
    user = GeneralController.get_user(request)
    body = request.get_json()
    code, resp = TicketsController.update_snooze_duration(ticket, body, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/pauseDuration', methods=['PATCH'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def update_ticket_pause(ticket=None):
    """ Update ticket pauseDuration
    """
    user = GeneralController.get_user(request)
    body = request.get_json()
    code, resp = TicketsController.update_pause_duration(ticket, body, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/defendant', methods=['PUT'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def update_ticket_defendant(ticket=None):
    """ Update ticket defendant
    """
    user = GeneralController.get_user(request)
    body = request.get_json()
    code, resp = TicketsController.update(ticket, body, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/emails', methods=['GET'])
@jsonify
@token_required
@perm_required
@catch_500
def get_mails(ticket=None):
    """ Get all emails sent and received for this ticket
    """
    code, resp = TicketsController.get_emails(ticket)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/status/<status>', methods=['PUT'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def update_status(ticket=None, status=None):
    """ Update ticket status
    """
    if status and status.lower() == 'closed':
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'To close ticket, please use Interact'}

    user = GeneralController.get_user(request)
    body = request.get_json()
    code, resp = TicketsController.update_status(ticket, status, body, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/templates/<template>', methods=['GET'])
@jsonify
@token_required
@perm_required
@catch_500
def get_ticket_prefetched_template(ticket=None, template=None):
    """ Get a template prefetched with ticket infos
    """
    code, resp = TemplatesController.get_prefetch_template(ticket, template)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/presets/<preset>', methods=['GET'])
@jsonify
@token_required
@perm_required
@catch_500
def get_ticket_prefetched_preset(ticket=None, preset=None):
    """ Get a template prefetched with ticket infos
    """
    user = GeneralController.get_user(request)
    code, resp = PresetsController.get_prefetch_preset(user, ticket, preset)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/tags', methods=['POST'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def add_ticket_tag(ticket=None):
    """ Add tag to ticket
    """
    user = GeneralController.get_user(request)
    body = request.get_json()
    code, resp = TicketsController.add_tag(ticket, body, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/tags/<tag>', methods=['DELETE'])
@jsonify
@token_required
@perm_required
@catch_500
def delete_ticket_tag(ticket=None, tag=None):
    """ Remove ticket tag
    """
    user = GeneralController.get_user(request)
    code, resp = TicketsController.remove_tag(ticket, tag, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/interact', methods=['POST'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def interact(ticket=None):
    """ Magic endpoint to save operator's time
    """
    user = GeneralController.get_user(request)
    body = request.get_json()
    code, resp = TicketsController.interact(ticket, body, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/actions/list', methods=['GET'])
@jsonify
@token_required
@perm_required
@catch_500
def get_actions(ticket=None):
    """
        List all available actions
    """
    user = GeneralController.get_user(request)
    code, resp = TicketsController.get_actions_list(ticket, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/jobs', methods=['GET'])
@jsonify
@token_required
@perm_required
@catch_500
def get_jobs(ticket=None):
    """
        Get actions status
    """
    code, resp = TicketsController.get_jobs_status(ticket)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/jobs', methods=['POST'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def schedule_job(ticket=None):
    """
        Schedule action
    """
    body = request.get_json()
    user = GeneralController.get_user(request)
    if not body.get('action') or not body.get('delay'):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing action or delay in body'}
    code, resp = TicketsController.schedule_asynchronous_job(ticket, body.get('action'), user, body.get('delay'))
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/jobs/<job>', methods=['DELETE'])
@jsonify
@token_required
@perm_required
@catch_500
def cancel_job(ticket=None, job=None):
    """
        Cancel action
    """
    user = GeneralController.get_user(request)
    code, resp = TicketsController.cancel_asynchronous_job(ticket, job, user)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/comments', methods=['POST'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def add_comment(ticket=None):
    """ Add comment to ticket
    """
    body = request.get_json()
    user = GeneralController.get_user(request)
    code, resp = CommentsController.create(body, ticket_id=ticket, user_id=user.id)
    return code, resp


@ticket_views.route('/api/tickets/<ticket>/comments/<comment>', methods=['PUT', 'DELETE'])
@jsonify
@token_required
@perm_required
@catch_500
def update_or_delete_comment(ticket=None, comment=None):
    """ Update or delete ticket comments
    """
    user = GeneralController.get_user(request)
    if request.method == 'PUT':
        body = request.get_json()
        code, resp = CommentsController.update(body, comment_id=comment, ticket_id=ticket, user_id=user.id)
    else:
        code, resp = CommentsController.delete(comment_id=comment, ticket_id=ticket, user_id=user.id)

    return code, resp


@ticket_views.route('/api/tickets/<ticket>/providers', methods=['GET'])
@jsonify
@token_required
@perm_required
@catch_500
def get_providers(ticket=None):
    """ Get ticket's providers
    """
    code, resp = TicketsController.get_providers(ticket)
    return code, resp
