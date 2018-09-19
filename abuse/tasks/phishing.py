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
    Phishing tasks
"""

from django.db.models import ObjectDoesNotExist

from . import helpers
from ..models import Report
from ..services.phishing import PhishingService


def close_because_all_down(report=None, denied_by=None):
    """
        Get or create a ticket and close it because all report's items are down

        :param `abuse.models.Report` report: A report instance
        :param int denied_by: The id of the `abuse.models.User`
            who takes the decision to close the ticket
    """
    if not isinstance(report, Report):
        try:
            report = Report.get(id=report)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            raise AssertionError("Report %d cannot be found in DB" % (report))

    if not report.ticket:
        report.ticket = helpers.create_ticket(report, denied_by)
        report.save()

    inject_proof = not bool(report.ticket.proof.count())

    # Send email to provider
    helpers.send_email(
        report.ticket,
        [report.provider.email],
        "no_more_content",
        inject_proof=inject_proof,
    )

    # Close ticket
    helpers.close_ticket(report.ticket, resolution_codename="no_more_content")

    # Add tag
    report.ticket.add_tag("phishing:autoclosed")


def unblock_url(url=None):
    """
        Unblock given url using PhishingService

        :param str url: The url to unblock
    """
    if not url:
        return

    PhishingService.unblock_url(url)


def feedback_to_phishing_service(screenshot_id=None, feedback=None):
    """
        Post phishing feedback for ML
        and scoring enhancement to Phishing Service

        :param str screenshot_id: The uuid of the screenshot_id
        :param bool feedback: Yes or not it's a phishing url
    """
    PhishingService.post_feedback(screenshot_id, feedback)
