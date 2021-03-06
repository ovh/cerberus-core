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
    Item reputation Controller
"""

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator, validate_ipv4_address
from werkzeug.exceptions import BadRequest

from ...services.reputation import ReputationService, ReputationServiceException


def get_ip_rbl_reputation(ip_addr):
    """
        Get RBL's reputation for given IP
    """
    try:
        validate_ipv4_address(ip_addr)
    except ValidationError:
        raise BadRequest("Not a valid IPV4")

    results = []

    if ReputationService.is_implemented():
        try:
            results = ReputationService.get_ip_rbl_reputations(ip_addr)
        except ReputationServiceException:
            pass

    return results


def get_ip_internal_reputation(ip_addr):
    """
        Internal checks
    """
    try:
        validate_ipv4_address(ip_addr)
    except ValidationError:
        raise BadRequest("Not a valid IPV4")

    results = []

    if ReputationService.is_implemented():
        try:
            results = ReputationService.get_ip_internal_reputations(ip_addr)
        except ReputationServiceException:
            pass

    return results


def get_ip_external_reputation(ip_addr):
    """
        External checks
    """
    try:
        validate_ipv4_address(ip_addr)
    except ValidationError:
        raise BadRequest("Not a valid IPV4")

    results = []

    if ReputationService.is_implemented():
        try:
            results = ReputationService.get_ip_external_reputations(ip_addr)
        except ReputationServiceException:
            pass

    return results


def get_ip_external_detail(ip_addr, source):
    """
        Get documents matching ip_addr and source
    """
    try:
        validate_ipv4_address(ip_addr)
    except ValidationError:
        raise BadRequest("Not a valid IPV4")

    results = []

    if ReputationService.is_implemented():
        try:
            results = ReputationService.get_ip_external_details(ip_addr, source)
        except ReputationServiceException:
            pass

    return results


def get_url_external_reputation(url):
    """
        External check for url
    """
    try:
        validate = URLValidator()
        validate(url)
    except (ValueError, ValidationError):
        raise BadRequest("Not a valid URL")

    results = []

    if ReputationService.is_implemented():
        try:
            results = ReputationService.get_url_external_reputations(url)
        except ReputationServiceException:
            pass

    return results


def get_ip_tools(ip_addr):
    """
        Generates link to online reputation tools
    """
    try:
        validate_ipv4_address(ip_addr)
    except ValidationError:
        raise BadRequest("Not a valid IPV4")

    results = []

    if ReputationService.is_implemented():
        try:
            results = ReputationService.get_ip_tools(ip_addr)
        except ReputationServiceException:
            pass

    return results
