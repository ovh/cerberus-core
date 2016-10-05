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
    Report views for Cerberus protected API.
"""

from io import BytesIO

from flask import Blueprint, json, g, make_response, request, send_file

from api.controllers import ReportItemsController, ReportsController
from decorators import jsonify, perm_required

report_views = Blueprint('report_views', __name__)


@report_views.route('/api/reports', methods=['GET'])
@jsonify
def get_all_reports():
    """ Get abuse reports

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    if 'filters' in request.args:
        code, resp, nb_reps = ReportsController.index(filters=request.args['filters'], user=g.user)
    else:
        code, resp, nb_reps = ReportsController.index(user=g.user)
    return code, resp


@report_views.route('/api/reports/<report>', methods=['GET'])
@jsonify
@perm_required
def get_report(report=None):
    """ Get a given report
    """
    code, resp = ReportsController.show(report)
    return code, resp


@report_views.route('/api/reports/<report>', methods=['PUT', 'DELETE'])
@jsonify
@perm_required
def update_report(report=None):
    """ Update a given report
    """
    if request.method == 'PUT':
        body = request.get_json()
        code, resp = ReportsController.update(report, body, g.user)
    else:
        code, resp = ReportsController.destroy(report)
    return code, resp


@report_views.route('/api/reports/<report>/items', methods=['GET'])
@jsonify
@perm_required
def get_report_items(report=None):
    """ Get all items for a given report

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    if 'filters' in request.args:
        code, resp = ReportItemsController.get_items_report(rep=report, filters=request.args['filters'])
    else:
        code, resp = ReportItemsController.get_items_report(rep=report)
    return code, resp


@report_views.route('/api/reports/<report>/items', methods=['POST'])
@jsonify
@perm_required
def create_report_item(report=None):
    """ Add item to report
    """
    body = request.get_json()
    body['report'] = report
    code, resp = ReportItemsController.create(body, g.user)
    return code, resp


@report_views.route('/api/reports/<report>/items/<item>', methods=['PUT', 'DELETE'])
@jsonify
@perm_required
def update_report_item(report=None, item=None):
    """ Update an item
    """
    if request.method == 'PUT':
        body = request.get_json()
        body['report'] = report
        code, resp = ReportItemsController.update(item, body, g.user)
    else:
        code, resp = ReportItemsController.delete_from_report(item, report, g.user)
    return code, resp


@report_views.route('/api/reports/<report>/items/<item>/screenshots', methods=['GET'])
@jsonify
@perm_required
def get_item_screenshot(report=None, item=None):
    """ Get available screenshots for given item
    """
    code, resp = ReportItemsController.get_screenshot(item, report)
    return code, resp


@report_views.route('/api/reports/<report>/items/screenshots', methods=['GET'])
@jsonify
@perm_required
def get_all_items_screenshot(report=None):
    """ Get all available screenshots for given report
    """
    if 'filters' in request.args:
        code, resp = ReportsController.get_items_screenshot(report=report, filters=request.args['filters'])
    else:
        code, resp = ReportsController.get_items_screenshot(report=report)
    return code, resp


@report_views.route('/api/reports/<report>/items/<item>/unblock', methods=['POST'])
@jsonify
@perm_required
def unblock_report_item(report=None, item=None):
    """ Unblock an item
    """
    code, resp = ReportItemsController.unblock_item(item_id=item, report_id=report)
    return code, resp


@report_views.route('/api/reports/<report>/raw', methods=['GET'])
@jsonify
@perm_required
def get_raw_report(report=None):
    """ Get raw email for a report
    """
    code, resp = ReportsController.get_raw(report)
    return code, resp


@report_views.route('/api/reports/<report>/dehtmlify', methods=['GET'])
@jsonify
@perm_required
def get_dehtmlified_report(report=None):
    """ Get raw email for a report
    """
    code, resp = ReportsController.get_dehtmlified(report)
    return code, resp


@report_views.route('/api/reports/<report>/attachments', methods=['GET'])
@jsonify
@perm_required
def get_all_report_attachments(report=None):
    """ Get attached documents for a report
    """
    if 'filters' in request.args:
        code, resp, nb_attached = ReportsController.get_all_attachments(report=report, filters=request.args['filters'])
    else:
        code, resp, nb_attached = ReportsController.get_all_attachments(report=report)
    return code, resp


@report_views.route('/api/reports/<report>/attachments/<attachment>', methods=['GET'])
@perm_required
def get_report_attachment(report=None, attachment=None):
    """ Get attached documents for a report
    """
    code, resp = ReportsController.get_attachment(report, attachment)
    if code != 200:
        return make_response(json.dumps(resp), code, {'content-type': 'application/json'})

    bytes_io = BytesIO(resp['raw'])
    return send_file(bytes_io, attachment_filename=resp['filename'], mimetype=resp['filetype'], as_attachment=True)


@report_views.route('/api/reports/<report>/tags', methods=['POST'])
@jsonify
@perm_required
def add_report_tag(report=None):
    """ Add tag to report
    """
    body = request.get_json()
    code, resp = ReportsController.add_tag(report, body)
    return code, resp


@report_views.route('/api/reports/<report>/tags/<tag>', methods=['DELETE'])
@jsonify
@perm_required
def delete_report_tag(report=None, tag=None):
    """ Delete report tag
    """
    code, resp = ReportsController.remove_tag(report, tag)
    return code, resp


@report_views.route('/api/reports/bulk', methods=['PUT', 'DELETE'])
@jsonify
@perm_required
def bulk_add_reports():
    """ Bulk add on reports
    """
    body = request.get_json()
    if request.method == 'PUT':
        code, resp = ReportsController.bulk_add(body, g.user, request.method)
    else:
        code, resp = ReportsController.bulk_delete(body, g.user, request.method)
    return code, resp


@report_views.route('/api/reports/<report>/feedback', methods=['POST'])
@jsonify
@perm_required
def post_feedback(report=None):
    """ Post feeback
    """
    body = request.get_json()
    code, resp = ReportsController.parse_screenshot_feedback(report, body, g.user)
    return code, resp
