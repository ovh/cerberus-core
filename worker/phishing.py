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
from datetime import datetime, timedelta
from Queue import Queue
from threading import Thread

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models import Q, ObjectDoesNotExist

import database
from abuse.models import (ServiceActionJob, Comment, ContactedProvider, Proof,
                          Report, Resolution, Tag, Ticket, TicketComment, User)
from adapters.services.phishing.abstract import PhishingServiceException
from factory.factory import ImplementationFactory
from utils import utils
from worker import Logger

BOT_USER = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])


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
            response.score
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
        report.ticket = __create_ticket(report, denied_by)
        report.save()

    # Add temp proof(s) for mail content
    temp_proofs = []
    if not report.ticket.proof.count():
        temp_proofs = __get_temp_proofs(report.ticket)

    # Send email to Provider
    try:
        validate_email(report.provider.email.strip())
        Logger.info(unicode('Sending email to provider'))
        __send_email(report.ticket, report.provider.email, settings.CODENAMES['no_more_content'])
        report.ticket.save()
        database.log_action_on_ticket(report.ticket, 'send an email to %s' % (report.provider.email))
        Logger.info(unicode('Mail sent to provider'))
        ImplementationFactory.instance.get_singleton_of('MailerServiceBase').close_thread(report.ticket)

        # Delete temp proof(s)
        for proof in temp_proofs:
            Proof.objects.filter(id=proof.id).delete()
    except (AttributeError, TypeError, ValueError, ValidationError):
        pass

    # Closing ticket and archiving report
    resolution = Resolution.objects.get(codename=settings.CODENAMES['no_more_content'])
    report.ticket.resolution = resolution
    report.ticket.previousStatus = report.ticket.status
    report.ticket.status = 'Closed'
    report.status = 'Archived'
    report.ticket.tags.remove(Tag.objects.get(name=settings.TAGS['phishing_autoreopen']))
    report.ticket.tags.add(Tag.objects.get(name=settings.TAGS['phishing_autoclosed']))

    msg = 'change status from %s to %s, reason : %s'
    database.log_action_on_ticket(
        report.ticket,
        msg % (report.ticket.previousStatus, report.ticket.status, report.ticket.resolution.codename)
    )

    report.ticket.save()
    report.save()
    Logger.info(unicode('Ticket %d and report %d closed' % (report.ticket.id, report.id)))


def __create_ticket(report, denied_by):
    """
        Create ticket
    """
    priority = report.provider.priority if report.provider.priority else 'Normal'
    ticket = database.create_ticket(report.defendant, report.category, report.service, priority=priority, attach_new=False)
    action = 'create this ticket with report %d from %s (%s ...)'
    database.log_action_on_ticket(ticket, action % (report.id, report.provider.email, report.subject[:30]))

    if denied_by:
        try:
            user = User.objects.get(id=denied_by)
        except (ObjectDoesNotExist, ValueError):
            Logger.error(unicode('User %d cannot be found in DB. Skipping...' % (denied_by)))
            return
        action = 'deny PhishToCheck report %d' % (report.id)
        database.log_action_on_ticket(ticket, action, user=user)

    Logger.info(unicode('Ticket %d created with report %d' % (ticket.id, report.id)))
    return ticket


def __get_temp_proofs(ticket):
    """
        Get report's ticket content
    """
    temp_proofs = []
    for report in ticket.reportTicket.all():
        content = 'From: %s\nDate: %s\nSubject: %s\n\n%s\n'
        temp_proofs.append(
            Proof.objects.create(
                content=content % (
                    report.provider.email,
                    report.receivedDate.strftime("%d/%m/%y %H:%M"),
                    report.subject,
                    utils.dehtmlify(report.body)
                ),
                ticket=report.ticket,
            )
        )
    return temp_proofs


def __send_email(ticket, email, codename, lang='EN'):
    """
        Wrapper to send email
    """
    prefetched_email = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').prefetch_email_from_template(
        ticket,
        codename,
        lang=lang,
    )
    ImplementationFactory.instance.get_singleton_of('MailerServiceBase').send_email(
        ticket,
        email,
        prefetched_email.subject,
        prefetched_email.body
    )


def block_url_and_mail(ticket_id=None, report_id=None):
    """
        Block url with PhishingService and send mail to defendant

        :param int ticket_id: The id of the Cerberus `abuse.models.Ticket`
        :param int report_id: The id of the Cerberus `abuse.models.Report`
    """
    if not all((ticket_id, report_id)):
        Logger.error(unicode('Invalid parameters submitted [ticket_id=%s, report_id=%s]' % (ticket_id, report_id)))
        return

    try:
        ticket = Ticket.objects.get(id=ticket_id)
        report = Report.objects.get(id=report_id)
        if not ticket.defendant or not ticket.service:
            Logger.error(unicode('Ticket %d has no defendant/service' % (ticket_id)))
            return
    except (ObjectDoesNotExist, ValueError):
        Logger.error(unicode('Ticket %d or report %d cannot be found in DB. Skipping...' % (ticket_id, report_id)))
        return

    for item in report.reportItemRelatedReport.all():
        if item.itemType == 'URL':
            ImplementationFactory.instance.get_singleton_of('PhishingServiceBase').block_url(item.rawItem, item.report)

    database.add_phishing_blocked_tag(report)
    __send_email(ticket, report.defendant.details.email, settings.CODENAMES['phishing_blocked'], report.defendant.details.lang)
    ticket = Ticket.objects.get(id=ticket.id)
    database.log_action_on_ticket(ticket, 'send an email to %s' % (ticket.defendant.details.email))

    ticket_snooze = settings.GENERAL_CONFIG['phishing']['wait']
    if not ticket.status == 'WaitingAnswer' and not ticket.snoozeDuration and not ticket.snoozeStart:
        ticket.previousStatus = ticket.status
        ticket.status = 'WaitingAnswer'
        ticket.snoozeDuration = ticket_snooze
        ticket.snoozeStart = datetime.now()

    ticket.save()
    Logger.info(unicode('Ticket %d now with status WaitingAnswer for %d' % (ticket_id, ticket_snooze)))


def __check_report_items_status(report_id, last, queue):
    """
        Thread checking if all down for a phishing report
    """
    queue.put(check_if_all_down(report=report_id, last=last))


def __close_phishing_ticket(ticket, reason=settings.CODENAMES['fixed_customer'], service_blocked=False):
    """
        Close ticket and add autoclosed Tag
    """
    # Send email to already contacted Provider(s)
    providers_emails = ContactedProvider.objects.filter(ticket_id=ticket.id).values_list('provider__email', flat=True).distinct()

    for email in providers_emails:
        try:
            validate_email(email.strip())
            __send_email(ticket, email, settings.CODENAMES['case_closed'])
            ticket.save()
            database.log_action_on_ticket(ticket, 'send an email to %s' % (email))
            Logger.info(unicode('Mail sent to provider %s' % (email)))
        except (AttributeError, TypeError, ValueError, ValidationError):
            pass

    if service_blocked:
        template = settings.CODENAMES['phishing_service_blocked']
    else:
        template = settings.CODENAMES['ticket_closed']

    __send_email(ticket, ticket.defendant.details.email, template, lang=ticket.defendant.details.lang)

    actions = []
    resolution = Resolution.objects.get(codename=reason)
    ticket.resolution = resolution
    ticket.previousStatus = ticket.status
    ticket.status = 'Closed'
    ticket.reportTicket.all().update(status='Archived')
    ticket.tags.remove(Tag.objects.get(name=settings.TAGS['phishing_autoreopen']))
    ticket.tags.add(Tag.objects.get(name=settings.TAGS['phishing_autoclosed']))
    ticket.save()

    msg = 'change status from %s to %s, reason : %s'
    actions.append(msg % (ticket.previousStatus, ticket.status, ticket.resolution.codename))
    actions.append('add tag %s ' % (settings.TAGS['phishing_autoclosed']))

    for action in actions:
        database.log_action_on_ticket(ticket, action)


def timeout(ticket_id=None):
    """
        If ticket timeout (Alarm), apply action on service (if defendant not internal/VIP)

        :param int ticket_id: The id of the Cerberus `abuse.models.Ticket`
    """
    if not ticket_id:
        Logger.error(unicode('Invalid parameters submitted [ticket_id=%s]' % (ticket_id)))
        return

    try:
        ticket = Ticket.objects.get(id=ticket_id)
        if not ticket.defendant or not ticket.service or ticket.status.lower() != 'alarm':
            Logger.error(unicode('Ticket %d is invalid (no defendant/service or not Alarm), Skipping...' % (ticket_id)))
            return
    except (ObjectDoesNotExist, ValueError):
        Logger.error(unicode('Ticket %d cannot be found in DB. Skipping...' % (ticket_id)))
        return

    if ticket.defendant.details.isInternal or ticket.defendant.details.isVIP:
        Logger.error(unicode("Ticket's defendant %s is internal or VIP, skipping" % (ticket.defendant.customerId)))
        ticket.status = ticket.previousStatus
        ticket.status = 'ActionError'
        database.log_action_on_ticket(ticket, 'change status from %s to %s' % (ticket.previousStatus, ticket.status), BOT_USER)
        comment = Comment.objects.create(user=BOT_USER, comment="Ticket's defendant is internal or VIP")
        TicketComment.objects.create(ticket=ticket, comment=comment)
        database.log_action_on_ticket(ticket, 'add comment', BOT_USER)
        ticket.save()
        return

    if ticket.jobs.count():
        Logger.error(unicode('Ticket %d has existing jobs, exiting ...' % (ticket_id)))
        return

    action = ImplementationFactory.instance.get_singleton_of('ActionServiceBase').get_action_for_timeout(ticket)
    if not action:
        Logger.error(unicode('Ticket %d service %s: action not found, exiting ...' % (ticket_id, ticket.service.componentType)))
        return

    if is_all_down_for_ticket(ticket):
        Logger.info(unicode('All items are down for ticket %d, Skipping ..' % (ticket_id)))
        return

    Logger.info(unicode('Executing action %s for ticket %d' % (action.name, ticket_id)))
    ticket.action = action
    database.log_action_on_ticket(ticket, 'set action: %s, execution now' % (action.name), BOT_USER)
    ticket.save()

    ip_addr = __get_ip_for_action(ticket)
    if not ip_addr:
        Logger.error(unicode('Error while gettting IP to block, exiting'))
        return

    # Apply action
    async_job = utils.scheduler.schedule(
        scheduled_time=datetime.utcnow() + timedelta(seconds=3),
        func='action.apply_action',
        kwargs={
            'ticket_id': ticket.id,
            'action_id': action.id,
            'ip_addr': ip_addr,
            'user_id': BOT_USER.id,
        },
        interval=1,
        repeat=1,
        result_ttl=500,
        timeout=3600,
    )

    Logger.info(unicode('Task has %s job id' % (async_job.id)))
    job = ServiceActionJob.objects.create(ip=ip_addr, action=action, asynchronousJobId=async_job.id, creationDate=datetime.now())
    ticket.jobs.add(job)
    ticket.save()
    Logger.info(unicode('All done, sending close notification to provider(s)'))
    ticket = Ticket.objects.get(id=ticket.id)
    __close_phishing_ticket(ticket, reason=settings.CODENAMES['fixed'], service_blocked=True)


def __get_ip_for_action(ticket):
    """
        Extract and check IP address
    """
    # Get ticket IP(s)
    reports = ticket.reportTicket.all()
    ips_on_ticket = [itm.ip for rep in reports for itm in rep.reportItemRelatedReport.filter(~Q(ip=None), itemType='IP')]
    ips_on_ticket.extend([itm.fqdnResolved for rep in reports for itm in rep.reportItemRelatedReport.filter(~Q(fqdnResolved=None), itemType__in=['FQDN', 'URL'])])
    ips_on_ticket = list(set(ips_on_ticket))

    if len(ips_on_ticket) != 1:
        Logger.error(unicode('Multiple or no IP on this ticket'))
        return

    return ips_on_ticket[0]


def is_all_down_for_ticket(ticket, last=5):
    """
        Check if all items for a ticket are down

        :param `Ticket` ticket : A Cerberus `abuse.models.Ticket` instance
        :param int last: Check for the 'last' entries
        :rtype: bool
        :returns: if all items are down
    """
    queue = Queue()
    threads = []

    # Check if there are still items up
    for report in ticket.reportTicket.all():
        thread = Thread(target=__check_report_items_status, args=(report.id, last, queue))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    results = [queue.get() for _ in xrange(ticket.reportTicket.count())]

    if all(results):
        return True
    else:
        return False


def feedback_to_phishing_service(screenshot_id=None, feedback=None):
    """
        Post phishing feedback for ML and scoring enhancement to Phishing Service

        :param str screenshot_id: The uuid of the screenshot_id
        :param bool feedback: Yes or not it's a phishing url
    """
    ImplementationFactory.instance.get_singleton_of('PhishingServiceBase').post_feedback(screenshot_id, feedback)
    Logger.debug(unicode('Feedback %s sent for %s' % (feedback, screenshot_id)))
