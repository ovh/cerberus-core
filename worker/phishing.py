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

from datetime import datetime

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models import ObjectDoesNotExist

import common
import database

from abuse.models import Proof, Report, Tag, Ticket
from adapters.services.phishing.abstract import PhishingServiceException
from factory.implementation import ImplementationFactory
from worker import Logger


def check_if_all_down(report=None, last=5):
    """ Check if all urls items for a report (phishing for example) are 'down'.

        :param `abuse.models.Report` report: A Cerberus `abuse.models.Report` instance to ping
        :param int last: Look for the n last record in db
        :return: the result
        :rtype: bool
    """
    if not isinstance(report, Report):
        try:
            report = Report.objects.get(id=report)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            Logger.error(unicode('Report %d cannot be found in DB. Skipping...' % (report)))
            return

    items = report.reportItemRelatedReport.all()
    items = list(set([item for item in items if item.itemType == 'URL']))
    if not items:
        return False

    country = report.defendant.details.country if report.defendant else 'FR'

    for item in items:
        __update_item_status(item, country)

    items = report.reportItemRelatedReport.all()
    items = list(set([item for item in items if item.itemType == 'URL']))
    scoring = {item.id: 0 for item in items}

    for item in items:
        status_score = database.get_item_status_score(item.id, last=last)
        for score in status_score:
            scoring[item.id] += score

    if all(v >= settings.GENERAL_CONFIG['phishing']['down_threshold'] for v in scoring.itervalues()):
        Logger.error(unicode('All urls are down for report %d' % (report.id)))
        return True

    Logger.error(unicode('Some url are still up for report %d' % (report.id)))
    return False


def __update_item_status(item, country='FR'):
    """
        Update item status
    """
    if item.itemType != 'URL':
        return

    try:
        Logger.debug(unicode('Checking status for url %s' % (item.rawItem,)))
        response = ImplementationFactory.instance.get_singleton_of('PhishingServiceBase').ping_url(item.rawItem, country=country)
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
        Create and close a ticket when all report's items are down

        :param `abuse.models.Report` report: A Cerberus `abuse.models.Report` instance
        :param int denied_by: The id of the `abuse.models.User` who takes the decision to close the ticket
    """
    if not isinstance(report, Report):
        try:
            report = Report.objects.get(id=report)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            Logger.error(unicode('Report %d cannot be found in DB. Skipping...' % (report)))
            return

    if not report.ticket:
        report.ticket = common.create_ticket(report, denied_by)
        report.save()

    # Add temp proof(s) for mail content
    temp_proofs = []
    if not report.ticket.proof.count():
        temp_proofs = common.get_temp_proofs(report.ticket)

    # Send email to Provider
    try:
        validate_email(report.provider.email.strip())
        Logger.info(unicode('Sending email to provider'))
        __send_email(report.ticket, report.provider.email, settings.CODENAMES['no_more_content'])
        report.ticket.save()
        Logger.info(unicode('Mail sent to provider'))
        ImplementationFactory.instance.get_singleton_of('MailerServiceBase').close_thread(report.ticket)

        # Delete temp proof(s)
        for proof in temp_proofs:
            Proof.objects.filter(id=proof.id).delete()
    except (AttributeError, TypeError, ValueError, ValidationError):
        pass

    # Closing ticket and add tags
    common.close_ticket(report, resolution_codename=settings.CODENAMES['no_more_content'])
    report.ticket.tags.remove(Tag.objects.get(name=settings.TAGS['phishing_autoreopen']))
    report.ticket.tags.add(Tag.objects.get(name=settings.TAGS['phishing_autoclosed']))
    Logger.info(unicode('Ticket %d and report %d closed' % (report.ticket.id, report.id)))


def __send_email(ticket, email, codename, lang='EN'):
    """
        Wrapper to send email
    """
    common.send_email(
        ticket,
        [email],
        codename,
        lang=lang,
    )


def block_url_and_mail(ticket_id=None, report_id=None):
    """
        Block url with PhishingService and send mail to defendant

        :param int ticket_id: The id of the Cerberus `abuse.models.Ticket`
        :param int report_id: The id of the Cerberus `abuse.models.Report`
    """
    if not isinstance(ticket_id, Ticket):
        try:
            ticket = Ticket.objects.get(id=ticket_id)
            if not ticket.defendant or not ticket.service:
                Logger.error(unicode('Ticket %d has no defendant/service' % (ticket_id)))
                return
        except (ObjectDoesNotExist, ValueError):
            Logger.error(unicode('Ticket %d cannot be found in DB. Skipping...' % (ticket_id)))
            return
    else:
        ticket = ticket_id

    if not isinstance(report_id, Report):
        try:
            report = Report.objects.get(id=report_id)
        except (ObjectDoesNotExist, ValueError):
            Logger.error(unicode('Report %d cannot be found in DB. Skipping...' % (report_id)))
            return
    else:
        report = report_id

    for item in report.reportItemRelatedReport.filter(itemType='URL'):
        ImplementationFactory.instance.get_singleton_of('PhishingServiceBase').block_url(item.rawItem, item.report)

    database.add_phishing_blocked_tag(report)
    __send_email(ticket, report.defendant.details.email, settings.CODENAMES['phishing_blocked'], report.defendant.details.lang)
    ticket = Ticket.objects.get(id=ticket.id)

    ticket_snooze = settings.GENERAL_CONFIG['phishing']['wait']
    if not ticket.status == 'WaitingAnswer' and not ticket.snoozeDuration and not ticket.snoozeStart:
        ticket.previousStatus = ticket.status
        ticket.status = 'WaitingAnswer'
        ticket.snoozeDuration = ticket_snooze
        ticket.snoozeStart = datetime.now()

    ticket.save()
    Logger.info(unicode('Ticket %d now with status WaitingAnswer for %d' % (ticket.id, ticket_snooze)))


def unblock_url(url=None):
    """
        Unblock given url using PhishingService

        :param str url: The url to unblock
    """
    if not url:
        return

    ImplementationFactory.instance.get_singleton_of('PhishingServiceBase').unblock_url(url)


def is_all_down_for_ticket(ticket, last=5, url_only=False):
    """
        Check if all items for a ticket are down

        :param `Ticket` ticket : A Cerberus `abuse.models.Ticket` instance
        :param int last: Check for the 'last' entries
        :param bool url_only: Check only report containing URL
        :rtype: bool
        :returns: if all items are down
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
    ImplementationFactory.instance.get_singleton_of('PhishingServiceBase').post_feedback(screenshot_id, feedback)
    Logger.debug(unicode('Feedback %s sent for %s' % (feedback, screenshot_id)))
