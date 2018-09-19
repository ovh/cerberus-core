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

from flask import Blueprint, g, request
from voluptuous import Any, Optional
from werkzeug.exceptions import Unauthorized

from ..cache import Cache
from ..decorators import admin_required, validate_body
from ..controllers import misc as MiscController
from ..controllers import providers as ProvidersController
from ..controllers import reportitems as ReportItemsController
from ..controllers import tickets as TicketsController

misc_views = Blueprint("misc_views", __name__)


@misc_views.route("/auth", methods=["POST"])
@validate_body({"name": unicode, "password": unicode})
def auth():
    """
        Check user/password and returns token if valid
    """
    body = request.get_json()
    authenticated, ret = MiscController.auth(body)
    if authenticated:
        return ret
    else:
        raise Unauthorized(ret)


@misc_views.route("/logout", methods=["POST"])
def logout():
    """
        Logout user
    """
    return MiscController.logout(request)


@misc_views.route("/ping", methods=["POST"])
def ping():
    """
        Keep alive between UX and API
    """
    return {"message": "pong"}


@misc_views.route("/tools/curl", methods=["GET"])
def get_url_http_headers():
    """
        Curl-like
    """
    return ReportItemsController.get_http_headers(request.args.get("url"))


@misc_views.route("/tools/whois", methods=["GET"])
def get_whois():
    """
        Whois-like
    """
    return ReportItemsController.get_whois(request.args.get("item"))


@misc_views.route("/notifications", methods=["GET"])
def get_user_notifications():
    """
        Get user notifications
    """
    return MiscController.get_notifications(g.user)


@misc_views.route("/monitor", methods=["GET"])
def monitor():
    """ Get api Infos
    """
    MiscController.monitor()
    return {"message": "I'm up !"}


@misc_views.route("/profiles", methods=["GET"])
@Cache.cached(timeout=43200)
def get_profiles():
    """ Get Abuse profiles
    """
    return MiscController.get_profiles()


@misc_views.route("/search", methods=["GET"])
def search():
    """ Search on tickets and reports

    """
    return MiscController.search(filters=request.args.get("filters"), user=g.user)


@misc_views.route("/users", methods=["GET"])
@Cache.cached(timeout=43200)
def get_users_infos():
    """ Get users infos
    """
    return MiscController.get_users_infos()


@misc_views.route("/users/me", methods=["GET"])
@Cache.cached(timeout=43200, current_user=True)
def get_logged_user():
    """ Get infos for logged user
    """
    return MiscController.get_users_infos(user=g.user.id)


@misc_views.route("/users/<user>", methods=["GET"])
@admin_required
def get_user(user=None):
    """ Get infos for a user
    """
    return MiscController.get_users_infos(user=user)


@misc_views.route("/users/<user>", methods=["PUT"])
@admin_required
@Cache.invalidate(routes=["/api/users", "/api/users/me"], clear_for_user=True)
@validate_body(
    {
        Optional("id"): int,
        Optional("email"): unicode,
        "username": unicode,
        "role": unicode,
        "profiles": [
            {"access": bool, "category": unicode, "profile": Any(None, unicode)}
        ],
    }
)
def update_user(user=None):
    """ Update user infos
    """
    body = request.get_json()
    return MiscController.update_user(user, body)


@misc_views.route("/status", methods=["GET"])
@Cache.cached(timeout=43200)
def get_all_status():
    """ Get all abuse status
    """
    return MiscController.status()


@misc_views.route("/resolutions", methods=["GET"])
@Cache.cached(timeout=43200)
def get_all_ticket_resolutions():
    """ Get all abuse status
    """
    return MiscController.get_ticket_resolutions()


@misc_views.route("/resolutions", methods=["POST"])
@admin_required
@Cache.invalidate(routes=["/api/resolutions"])
@validate_body({"codename": unicode})
def add_ticket_resolution():
    """ Get all abuse status
    """
    body = request.get_json()
    return MiscController.add_ticket_resolution(body)


@misc_views.route("/resolutions/<resolution>", methods=["PUT"])
@admin_required
@Cache.invalidate(routes=["/api/resolutions"])
@validate_body({Optional("id"): int, "codename": unicode})
def update_ticket_resolution(resolution=None):
    """ Get all abuse status
    """
    body = request.get_json()
    return MiscController.update_ticket_resolution(resolution, body)


@misc_views.route("/resolutions/<resolution>", methods=["DELETE"])
@admin_required
@Cache.invalidate(routes=["/api/resolutions"])
def delete_ticket_resolution(resolution=None):
    """ Get all abuse status
    """
    return MiscController.delete_ticket_resolution(resolution)


@misc_views.route("/status/<model>", methods=["GET"])
@Cache.cached(timeout=43200)
def get_status(model=None):
    """ Get status list for ticket or report
    """
    return MiscController.status(model=model)


@misc_views.route("/toolbar", methods=["GET"])
@Cache.cached(timeout=180, current_user=True)
def get_toolbar():
    """ Get Abuse toolbar
    """
    return MiscController.toolbar(user=g.user)


@misc_views.route("/dashboard", methods=["GET"])
@Cache.cached(timeout=3600, current_user=True)
def get_dashboard():
    """ Get Abuse dashboard
    """
    return MiscController.dashboard(user=g.user)


@misc_views.route("/priorities/ticket", methods=["GET"])
@Cache.cached(timeout=43200)
def get_ticket_priorities():
    """ Get list of ticket priorities
    """
    return TicketsController.get_priorities()


@misc_views.route("/priorities/provider", methods=["GET"])
@Cache.cached(timeout=43200)
def get_providers_priorities():
    """ Get list of providers priorities
    """
    return ProvidersController.get_priorities()


@misc_views.route("/mass-contact", methods=["GET"])
def get_mass_contact():
    """
        List all created mass-contact campaigns
    """
    return MiscController.get_mass_contact(filters=request.args.get("filters"))


@misc_views.route("/mass-contact", methods=["POST"])
@validate_body(
    {
        "ips": list,
        "campaignName": unicode,
        "category": unicode,
        "email": {"subject": unicode, "body": unicode},
    }
)
def post_mass_contact():
    """
    Massively contact defendants based on ip addresses list

    **Example request**:

    .. sourcecode:: http

       POST /mass-contact HTTP/1.1
       Content-Type: application/json

       {
           "ips": ["1.2.3.4", "5.6.7.8"],
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
    return MiscController.post_mass_contact(body, g.user)


@misc_views.route("/roles", methods=["GET"])
@Cache.cached(timeout=43200)
def get_cerberus_roles():
    """
        List all Cerberus `abuse.models.Role`
    """
    return MiscController.get_roles()


@misc_views.route("/my-tickets", methods=["GET"])
def get_user_tickets():
    """ Get abuse tickets for logged g.user
    """
    resp, _ = TicketsController.get_tickets(
        filters=request.args.get("filters"), treated_by=g.user.id, user=g.user
    )
    return resp
