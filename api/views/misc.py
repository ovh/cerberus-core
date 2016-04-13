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
    Misc views for Cerberus protected API.
"""

from django.conf import settings
from flask import Blueprint, request

from api.controllers import (GeneralController, ProvidersController,
                             TicketsController)
from decorators import (admin_required, catch_500, json_required, jsonify,
                        token_required, validate_body)

misc_views = Blueprint('misc_views', __name__)


@misc_views.route('/api/auth', methods=['POST'])
@jsonify
@json_required
@catch_500
def auth():
    """
        Check user/password and returns token if valid
    """
    if settings.API.get('forwarded_host'):
        try:
            if not request.environ['HTTP_X_FORWARDED_HOST'] == settings.API['forwarded_host']:
                return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid HTTP_X_FORWARDED_HOST'}
        except KeyError:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing HTTP_X_FORWARDED_HOST'}

    body = request.get_json()
    authenticated, ret = GeneralController.auth(body)
    if authenticated:
        return 200, ret
    else:
        return 401, {'status': 'Unauthorized', 'code': 401, 'message': ret}


@misc_views.route('/api/logout', methods=['POST'])
@jsonify
@token_required
@catch_500
def logout():
    """ Logout user
    """
    code, resp = GeneralController.logout(request)
    return code, resp


@misc_views.route('/api/ping', methods=['POST'])
@jsonify
@token_required
@catch_500
def ping():
    """ Keep alive between UX and API
    """
    return 200, {'status': 'OK', 'code': 200}


@misc_views.route('/api/notifications', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_user_notifications():
    """ Get user notifications
    """
    user = GeneralController.get_user(request)
    code, resp = GeneralController.get_notifications(user)
    return code, resp


@misc_views.route('/api/monitor', methods=['GET'])
@jsonify
@catch_500
def monitor():
    """ Get api Infos
    """
    GeneralController.monitor()
    return 200, {'status': 'OK', 'code': 200}


@misc_views.route('/api/profiles', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_profiles():
    """ Get Abuse profiles
    """
    code, resp = GeneralController.get_profiles()
    return code, resp


@misc_views.route('/api/search', methods=['GET'])
@jsonify
@token_required
@catch_500
def search():
    """ Search on tickets and reports

        Filtering is possible through "filters" query string : filters=%7B"type":"reports"%7D&page=1
        JSON double encoded format
    """
    user = GeneralController.get_user(request)
    if 'filters' in request.args:
        code, resp = GeneralController.search(filters=request.args['filters'], user=user)
        return code, resp


@misc_views.route('/api/users', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_users_infos():
    """ Get users infos
    """
    user = GeneralController.get_user(request)
    if user.is_superuser:
        code, resp = GeneralController.get_users_infos()
    else:
        code, resp = GeneralController.get_users_login()
    return code, resp


@misc_views.route('/api/users/me', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_logged_user():
    """ Get infos for logged user
    """
    user = GeneralController.get_user(request)
    valid, ret = GeneralController.get_users_infos(user=user.id)
    if not valid:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': ret}
    else:
        return 200, ret


@misc_views.route('/api/users/<user>', methods=['GET'])
@jsonify
@token_required
@admin_required
@catch_500
def get_user(user=None):
    """ Get infos for a user
    """
    code, resp = GeneralController.get_users_infos(user=user)
    return code, resp


@misc_views.route('/api/users/<user>', methods=['PUT'])
@jsonify
@token_required
@admin_required
@json_required
@catch_500
def update_user(user=None):
    """ Update user infos
    """
    body = request.get_json()
    code, resp = GeneralController.update_user(user, body)
    return code, resp


@misc_views.route('/api/status', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_all_status():
    """ Get all abuse status
    """
    return 200, GeneralController.status()


@misc_views.route('/api/resolutions', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_all_ticket_resolutions():
    """ Get all abuse status
    """
    return 200, GeneralController.get_ticket_resolutions()


@misc_views.route('/api/resolutions', methods=['POST'])
@jsonify
@token_required
@admin_required
@json_required
@catch_500
def add_ticket_resolution():
    """ Get all abuse status
    """
    body = request.get_json()
    code, resp = GeneralController.add_ticket_resolution(body)
    return code, resp


@misc_views.route('/api/resolutions/<resolution>', methods=['PUT'])
@jsonify
@token_required
@admin_required
@json_required
@catch_500
def update_ticket_resolution(resolution=None):
    """ Get all abuse status
    """
    body = request.get_json()
    code, resp = GeneralController.update_ticket_resolution(resolution, body)
    return code, resp


@misc_views.route('/api/resolutions/<resolution>', methods=['DELETE'])
@jsonify
@token_required
@admin_required
@catch_500
def delete_ticket_resolution(resolution=None):
    """ Get all abuse status
    """
    code, resp = GeneralController.delete_ticket_resolution(resolution)
    return code, resp


@misc_views.route('/api/status/<model>', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_status(model=None):
    """ Get status list for ticket or report
    """
    return 200, GeneralController.status(model=model)


@misc_views.route('/api/toolbar', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_toolbar():
    """ Get Abuse toolbar
    """
    user = GeneralController.get_user(request)
    code, resp = GeneralController.toolbar(user=user)
    return code, resp


@misc_views.route('/api/dashboard', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_dashboard():
    """ Get Abuse dashboard
    """
    user = GeneralController.get_user(request)
    code, resp = GeneralController.dashboard(user=user)
    return code, resp


@misc_views.route('/api/priorities/ticket', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_ticket_priorities():
    """ Get list of ticket priorities
    """
    return 200, TicketsController.get_priorities()


@misc_views.route('/api/priorities/provider', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_providers_priorities():
    """ Get list of providers priorities
    """
    return 200, ProvidersController.get_priorities()


@misc_views.route('/api/ip/reports/<ip_addr>', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_ip_report_count(ip_addr=None):
    """ Get hits for an ip
    """
    code, resp = GeneralController.get_ip_report_count(ip=ip_addr)
    return code, resp


@misc_views.route('/api/mass-contact', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_mass_contact():
    """
        List all created mass-contact campaigns
    """
    code, resp = GeneralController.get_mass_contact(filters=request.args.get('filters'))
    return code, resp


@misc_views.route('/api/mass-contact', methods=['POST'])
@jsonify
@token_required
@catch_500
@validate_body({'ips': list, 'campaignName': unicode, 'category': unicode, 'email': {'subject': unicode, 'body': unicode}})
def post_mass_contact():
    """
    Massively contact defendants based on ip addresses list

    **Example request**:

    .. sourcecode:: http

       POST /api/mass-contact HTTP/1.1
       Content-Type: application/json

       {
           "ips": ["1.2.3.4", "5.6.7.8.9],
           "campaignName": "ntp_amp_mars_2016",
           "category": "Network Attack"
           "email": {
               "subject": "blah",
               "body": "blah blah",
            }
       }

    :reqjson list ips: The list of involved ip addresses
    :reqjson str category: The category of the campaign
    :reqjson str campaignName: The name of the campaign
    :reqjson dict email: The email to send (containing 'subject' and 'body')

    :status 200: when campagin is successfully created
    :status 400: when parameters are missing or invalid
    """
    body = request.get_json()
    user = GeneralController.get_user(request)
    code, resp = GeneralController.post_mass_contact(body, user)
    return code, resp
