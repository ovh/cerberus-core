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
from flask import Blueprint, g, request
from voluptuous import Any, Optional
from werkzeug.exceptions import BadRequest, Unauthorized

from api.controllers import (GeneralController, ProvidersController,
                             ReportItemsController, TicketsController)
from decorators import (admin_required, Cached, InvalidateCache,
                        validate_body)

misc_views = Blueprint('misc_views', __name__)


@misc_views.route('/api/auth', methods=['POST'])
@validate_body({'name': unicode, 'password': unicode})
def auth():
    """
        Check user/password and returns token if valid
    """
    if settings.API.get('forwarded_host'):
        try:
            if not request.environ['HTTP_X_FORWARDED_HOST'] == settings.API['forwarded_host']:
                raise BadRequest('Invalid HTTP_X_FORWARDED_HOST')
        except KeyError:
            raise BadRequest('Missing HTTP_X_FORWARDED_HOST')

    body = request.get_json()
    authenticated, ret = GeneralController.auth(body)
    if authenticated:
        return ret
    else:
        raise Unauthorized(ret)


@misc_views.route('/api/logout', methods=['POST'])
def logout():
    """
        Logout user
    """
    return GeneralController.logout(request)


@misc_views.route('/api/ping', methods=['POST'])
def ping():
    """
        Keep alive between UX and API
    """
    return {'message': 'pong'}


@misc_views.route('/api/tools/curl', methods=['GET'])
def get_url_http_headers():
    """
        Curl-like
    """
    return ReportItemsController.get_http_headers(request.args.get('url'))


@misc_views.route('/api/tools/whois', methods=['GET'])
def get_whois():
    """
        Whois-like
    """
    return ReportItemsController.get_whois(request.args.get('item'))


@misc_views.route('/api/notifications', methods=['GET'])
def get_user_notifications():
    """
        Get user notifications
    """
    return GeneralController.get_notifications(g.user)


@misc_views.route('/api/monitor', methods=['GET'])
def monitor():
    """ Get api Infos
    """
    GeneralController.monitor()
    return {'message': "I'm up !"}


@misc_views.route('/api/profiles', methods=['GET'])
@Cached(timeout=43200)
def get_profiles():
    """ Get Abuse profiles
    """
    return GeneralController.get_profiles()


@misc_views.route('/api/search', methods=['GET'])
def search():
    """ Search on tickets and reports

        Filtering is possible through "filters" query string : filters=%7B"type":"reports"%7D&page=1
        JSON double encoded format
    """
    return GeneralController.search(filters=request.args.get('filters'), user=g.user)


@misc_views.route('/api/users', methods=['GET'])
@Cached(timeout=43200)
def get_users_infos():
    """ Get users infos
    """
    return GeneralController.get_users_infos()


@misc_views.route('/api/users/me', methods=['GET'])
@Cached(timeout=43200, current_user=True)
def get_logged_user():
    """ Get infos for logged user
    """
    return GeneralController.get_users_infos(user=g.user.id)


@misc_views.route('/api/users/<user>', methods=['GET'])
@admin_required
def get_user(user=None):
    """ Get infos for a user
    """
    return GeneralController.get_users_infos(user=user)


@misc_views.route('/api/users/<user>', methods=['PUT'])
@admin_required
@InvalidateCache(routes=['/api/users', '/api/users/me'], clear_for_user=True)
@validate_body({
    Optional('id'): int,
    Optional('email'): unicode,
    'username': unicode,
    'role': unicode,
    'profiles': [{
        'access': bool,
        'category': unicode,
        'profile': Any(None, unicode),
    }]
})
def update_user(user=None):
    """ Update user infos
    """
    body = request.get_json()
    return GeneralController.update_user(user, body)


@misc_views.route('/api/status', methods=['GET'])
@Cached(timeout=43200)
def get_all_status():
    """ Get all abuse status
    """
    return GeneralController.status()


@misc_views.route('/api/resolutions', methods=['GET'])
@Cached(timeout=43200)
def get_all_ticket_resolutions():
    """ Get all abuse status
    """
    return GeneralController.get_ticket_resolutions()


@misc_views.route('/api/resolutions', methods=['POST'])
@admin_required
@InvalidateCache(routes=['/api/resolutions'])
@validate_body({'codename': unicode})
def add_ticket_resolution():
    """ Get all abuse status
    """
    body = request.get_json()
    return GeneralController.add_ticket_resolution(body)


@misc_views.route('/api/resolutions/<resolution>', methods=['PUT'])
@admin_required
@InvalidateCache(routes=['/api/resolutions'])
@validate_body({
    Optional('id'): int,
    'codename': unicode
})
def update_ticket_resolution(resolution=None):
    """ Get all abuse status
    """
    body = request.get_json()
    return GeneralController.update_ticket_resolution(resolution, body)


@misc_views.route('/api/resolutions/<resolution>', methods=['DELETE'])
@admin_required
@InvalidateCache(routes=['/api/resolutions'])
def delete_ticket_resolution(resolution=None):
    """ Get all abuse status
    """
    return GeneralController.delete_ticket_resolution(resolution)


@misc_views.route('/api/status/<model>', methods=['GET'])
@Cached(timeout=43200)
def get_status(model=None):
    """ Get status list for ticket or report
    """
    return GeneralController.status(model=model)


@misc_views.route('/api/toolbar', methods=['GET'])
@Cached(timeout=180, current_user=True)
def get_toolbar():
    """ Get Abuse toolbar
    """
    return GeneralController.toolbar(user=g.user)


@misc_views.route('/api/dashboard', methods=['GET'])
@Cached(timeout=3600, current_user=True)
def get_dashboard():
    """ Get Abuse dashboard
    """
    return GeneralController.dashboard(user=g.user)


@misc_views.route('/api/priorities/ticket', methods=['GET'])
@Cached(timeout=43200)
def get_ticket_priorities():
    """ Get list of ticket priorities
    """
    return TicketsController.get_priorities()


@misc_views.route('/api/priorities/provider', methods=['GET'])
@Cached(timeout=43200)
def get_providers_priorities():
    """ Get list of providers priorities
    """
    return ProvidersController.get_priorities()


@misc_views.route('/api/mass-contact', methods=['GET'])
def get_mass_contact():
    """
        List all created mass-contact campaigns
    """
    return GeneralController.get_mass_contact(filters=request.args.get('filters'))


@misc_views.route('/api/mass-contact', methods=['POST'])
@validate_body({
    'ips': list,
    'campaignName': unicode,
    'category': unicode,
    'email': {
        'subject': unicode,
        'body': unicode
    }
})
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

    :status 200: when campaign is successfully created
    :status 400: when parameters are missing or invalid
    """
    body = request.get_json()
    return GeneralController.post_mass_contact(body, g.user)


@misc_views.route('/api/roles', methods=['GET'])
@Cached(timeout=43200)
def get_cerberus_roles():
    """
        List all Cerberus `abuse.models.Role`
    """
    return GeneralController.get_roles()
