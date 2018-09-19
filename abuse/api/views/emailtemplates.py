# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017, OVH SAS
#
# This file is part of Cerberus.
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
    Email Templates views for Cerberus API.
"""

from flask import Blueprint, request

from ..cache import Cache
from ..decorators import admin_required
from ..controllers import templates as TemplatesController


email_templates_views = Blueprint(
    "email_templates_views", __name__, url_prefix="/emailTemplates"
)


@email_templates_views.route("", methods=["GET"])
@Cache.cached(timeout=43200)
def get_all_templates():
    """ Get all Abuse mail templates
    """
    return TemplatesController.get_templates(filters=request.args.get("filters"))


@email_templates_views.route("/<template>", methods=["GET"])
@Cache.cached(timeout=43200)
def get_template(template=None):
    """ Get a given email template
    """
    return TemplatesController.show(template)


@email_templates_views.route("", methods=["POST"])
@admin_required
@Cache.invalidate(routes=["/api/emailTemplates"])
def create_templates():
    """ Add an email template
    """
    body = request.get_json()
    return TemplatesController.create(body)


@email_templates_views.route("/<template>", methods=["PUT", "DELETE"])
@admin_required
@Cache.invalidate(routes=["/api/emailTemplates"])
def update_template(template=None):
    """ Update an email template
    """
    if request.method == "PUT":
        body = request.get_json()
        return TemplatesController.update(template, body)

    return TemplatesController.destroy(template)


@email_templates_views.route("/languages", methods=["GET"])
@Cache.cached(timeout=43200)
def get_supported_languages():
    """ Get application supported languages
    """
    return TemplatesController.get_supported_languages()


@email_templates_views.route("/recipientsType", methods=["GET"])
@Cache.cached(timeout=43200)
def get_recipients_type():
    """ Get application supported languages
    """
    return TemplatesController.get_recipients_type()
