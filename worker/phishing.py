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
    Phishing functions for worker
"""

from django.conf import settings
from django.db.models import ObjectDoesNotExist

import common
import database

from abuse.models import Report, Tag
from adapters.services.phishing.abstract import PhishingServiceException
from factory.implementation import ImplementationFactory as implementations
from worker import Logger

DOWN_THRESHOLD = settings.GENERAL_CONFIG['phishing']['down_threshold']


def check_if_all_down(report=None, last=5, try_screenshot=True):
    """
        Check if all urls items for a report (phishing for example) are 'down'.

        :param `abuse.models.Report` report: A Cerberus `abuse.models.Report` instance to ping
        :param int last: Look for the n last record in db
        :param bool try_screenshot: Try to take a screenshot for the url
        :return: the result
        :rtype: bool
    """
    if not isinstance(report, Report):
        try:
            report = Report.objects.get(id=report)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            raise AssertionError('Report %d cannot be found in DB')

    # Check if report has URL items
    items = report.reportItemRelatedReport.all()
    items = list(set([item for item in items if item.itemType == 'URL']))
    if not items:  # No urls items found
        return False

    # Get current items score
    items_score = _get_items_score(report, items, last, try_screenshot)

    if all(v >= DOWN_THRESHOLD for v in items_score.itervalues()):
        Logger.error(unicode('All urls are down for report %d' % (report.id)))
        return True

    Logger.error(unicode('Some url are still up for report %d' % (report.id)))
    return False


def _get_items_score(report, items, last=5, try_screenshot=True):

    country = report.defendant.details.country if report.defendant else 'FR'

    for item in items:
        _update_item_status(item, country, try_screenshot)

    items = report.reportItemRelatedReport.all()
    items = list(set([item for item in items if item.itemType == 'URL']))
    scoring = {item.id: 0 for item in items}

    for item in items:
        status_score = database.get_item_status_score(item.id, last=last)
        for score in status_score:
            scoring[item.id] += score

    return scoring


def _update_item_status(item, country='FR', try_screenshot=True):

    if item.itemType != 'URL':
        return

    try:
        Logger.debug(unicode('Checking status for url %s' % (item.rawItem,)))
        response = implementations.instance.get_singleton_of(
            'PhishingServiceBase'
        ).ping_url(
            item.rawItem,
            country=country,
            try_screenshot=try_screenshot
        )
        database.insert_url_status(
            item,
            response.direct_status,
            response.proxied_status,
            response.http_code,
            response.score,
            response.is_phishing,
        )
    except PhishingServiceException:
        pass


def close_because_all_down(report=None, denied_by=None):
    """
        Get or create a ticket and close it because all report's items are down

        :param `abuse.models.Report` report: A Cerberus `abuse.models.Report` instance
        :param int denied_by: The id of the `abuse.models.User`
            who takes the decision to close the ticket
    """
    if not isinstance(report, Report):
        try:
            report = Report.objects.get(id=report)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            raise AssertionError('Report %d cannot be found in DB' % (report))

    if not report.ticket:
        report.ticket = common.create_ticket(report, denied_by)
        report.save()

    inject_proof = not bool(report.ticket.proof.count())

    # Send email to provider
    common.send_email(
        report.ticket,
        [report.provider.email],
        settings.CODENAMES['no_more_content'],
        inject_proof=inject_proof
    )

    # Close ticket
    common.close_ticket(
        report.ticket,
        resolution_codename=settings.CODENAMES['no_more_content']
    )

    # Add tag
    report.ticket.tags.add(Tag.objects.get(
        name=settings.TAGS['phishing_autoclosed'],
        tagType='Ticket'
    ))


def unblock_url(url=None):
    """
        Unblock given url using PhishingService

        :param str url: The url to unblock
    """
    if not url:
        return

    implementations.instance.get_singleton_of('PhishingServiceBase').unblock_url(url)


def is_all_down_for_ticket(ticket, last=5, url_only=False):
    """
        Check if all items for a ticket are down

        :param `Ticket` ticket : A Cerberus `abuse.models.Ticket` instance
        :param int last: Check for the 'last' entries
        :param bool url_only: Check only report containing URL
        :rtype: bool
        :return: if all items are down
    """
    results = []
    # Check if there are still items up
    for report in ticket.reportTicket.all():
        if url_only:
            if report.reportItemRelatedReport.filter(itemType='URL').exists():
                results.append(check_if_all_down(report=report, last=last))
        else:
            results.append(check_if_all_down(report=report, last=last))

    return bool(all(results))


def feedback_to_phishing_service(screenshot_id=None, feedback=None):
    """
        Post phishing feedback for ML and scoring enhancement to Phishing Service

        :param str screenshot_id: The uuid of the screenshot_id
        :param bool feedback: Yes or not it's a phishing url
    """
    implementations.instance.get_singleton_of(
        'PhishingServiceBase'
    ).post_feedback(
        screenshot_id,
        feedback
    )
