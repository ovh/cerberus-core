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
    Ticket functions for worker
"""

import hashlib
import inspect
import operator

from collections import Counter
from datetime import datetime, timedelta
from time import mktime, sleep, time

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email, validate_ipv46_address
from django.db import transaction
from django.db.models import Q, ObjectDoesNotExist
from django.template import Context, loader

import common
import database
import phishing

from abuse.models import (Category, Comment, ContactedProvider,
                          MassContactResult, Report, ReportItem,
                          Resolution, Tag, Ticket, TicketComment,
                          ServiceActionJob, User)
from adapters.dao.customer.abstract import CustomerDaoException
from factory.factory import ImplementationFactory
from utils import pglocks, schema, utils
from worker import Logger

BOT_USER = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

WORKER_TICKET_FUNC = (
    'ticket.timeout',
    'action.apply_if_no_reply'
)

WAITING = 'WaitingAnswer'
PAUSED = 'Paused'
ALARM = 'Alarm'

STATUS_SEQUENCE = [WAITING, ALARM, WAITING]


def delay_jobs(ticket=None, delay=None, back=True):
    """
        Delay pending jobs for given `abuse.models.Ticket`

        :param `abuse.models.Ticket` ticket: The Cerberus ticket
        :param int delay: Postpone duration
        :param bool back: In case of unpause, reschedule jobs with effectively elapsed time
    """
    if not delay:
        Logger.error(unicode('Missing delay. Skipping...'))
        return

    if not isinstance(ticket, Ticket):
        try:
            ticket = Ticket.objects.get(id=ticket)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            Logger.error(unicode('Ticket %d cannot be found in DB. Skipping...' % (ticket)))
            return

    # a job is here a tuple (Job instance, datetime instance)
    pending_jobs = {job[0].id: job for job in utils.scheduler.get_jobs(until=timedelta(days=7), with_times=True)}

    for job in ticket.jobs.all():
        if pending_jobs.get(job.asynchronousJobId):
            current_date = pending_jobs[job.asynchronousJobId][1]
            new_date = current_date - delay if back else current_date + delay
            utils.scheduler.change_execution_time(
                pending_jobs[job.asynchronousJobId][0],
                new_date
            )


def timeout(ticket_id=None):
    """
        If ticket timeout , apply action on service (if defendant not internal/VIP) and ticket is not assigned

        :param int ticket_id: The id of the Cerberus `abuse.models.Ticket`
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (AttributeError, ObjectDoesNotExist, ValueError):
        Logger.error(unicode('Ticket %d cannot be found in DB. Skipping...' % (ticket_id)))
        return

    if not _check_timeout_ticket_conformance(ticket):
        return

    action = ImplementationFactory.instance.get_singleton_of('ActionServiceBase').get_action_for_timeout(ticket)
    if not action:
        Logger.error(unicode('Ticket %d service %s: action not found, exiting ...' % (ticket_id, ticket.service.componentType)))
        return

    # Maybe customer fixed, closing ticket
    if ticket.category.name.lower() == 'phishing' and phishing.is_all_down_for_ticket(ticket):
        Logger.info(unicode('All items are down for ticket %d, closing ticket' % (ticket_id)))
        close_ticket(ticket, reason=settings.CODENAMES['fixed_customer'], service_blocked=False)
        return

    # Getting ip for action
    ip_addr = _get_ip_for_action(ticket)
    if not ip_addr:
        Logger.error(unicode('Error while getting IP for action, exiting'))
        ticket.status = ticket.previousStatus
        ticket.status = 'ActionError'
        database.log_action_on_ticket(
            ticket=ticket,
            action='change_status',
            previous_value=ticket.previousStatus,
            new_value=ticket.status
        )
        comment = Comment.objects.create(user=BOT_USER, comment='None or multiple ip addresses for this ticket')
        TicketComment.objects.create(ticket=ticket, comment=comment)
        database.log_action_on_ticket(
            ticket=ticket,
            action='add_comment'
        )
        ticket.save()
        return

    # Apply action
    service_action_job = _apply_timeout_action(ticket, ip_addr, action)
    if not service_action_job.result:
        Logger.debug(unicode('Error while executing service action, exiting'))
        return

    Logger.info(unicode('All done, sending close notification to provider(s)'))
    ticket = Ticket.objects.get(id=ticket.id)

    # Closing ticket
    close_ticket(ticket, reason=settings.CODENAMES['fixed'], service_blocked=True)


def _check_timeout_ticket_conformance(ticket):

    if not ticket.defendant or not ticket.service:
        Logger.error(unicode('Ticket %d is invalid (no defendant/service), skipping...' % (ticket.id)))
        return False

    if ticket.status.lower() in ['closed', 'answered']:
        Logger.error(unicode('Ticket %d is invalid (no defendant/service or not Alarm), Skipping...' % (ticket.id)))
        return False

    if ticket.category.name.lower() not in ['phishing', 'copyright']:
        Logger.error(unicode('Ticket %d is in wrong category (%s, Skipping...' % (ticket.id, ticket.category.name)))
        return False

    if ticket.treatedBy:
        Logger.error(unicode('Ticket is %d assigned, skipping' % (ticket.id)))
        return False

    if ticket.jobs.count():
        Logger.error(unicode('Ticket %d has existing jobs, exiting ...' % (ticket.id)))
        return False

    return True


def _apply_timeout_action(ticket, ip_addr, action):

    Logger.info(unicode('Executing action %s for ticket %d' % (action.name, ticket.id)))
    ticket.action = action
    database.log_action_on_ticket(
        ticket=ticket,
        action='set_action',
        action_name=action.name
    )
    ticket.save()
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

    while not async_job.is_finished:
        sleep(5)

    return async_job


def close_ticket(ticket, reason=settings.CODENAMES['fixed_customer'], service_blocked=False):
    """
        Close ticket and add autoclosed Tag
    """
    # Send "case closed" email to already contacted Provider(s)
    providers_emails = ContactedProvider.objects.filter(ticket_id=ticket.id).values_list('provider__email', flat=True).distinct()

    for email in providers_emails:
        try:
            validate_email(email.strip())
            _send_email(ticket, email, settings.CODENAMES['case_closed'])
            ticket.save()
            Logger.info(unicode('Mail sent to provider %s' % (email)))
        except (AttributeError, TypeError, ValueError, ValidationError):
            pass

    if service_blocked:
        template = settings.CODENAMES['service_blocked']
    else:
        template = settings.CODENAMES['ticket_closed']

    # Send "ticket closed" email to defendant
    _send_email(ticket, ticket.defendant.details.email, template, lang=ticket.defendant.details.lang)
    if ticket.mailerId:
        ImplementationFactory.instance.get_singleton_of('MailerServiceBase').close_thread(ticket)

    resolution = Resolution.objects.get(codename=reason)
    ticket.resolution = resolution
    ticket.previousStatus = ticket.status
    ticket.status = 'Closed'
    ticket.reportTicket.all().update(status='Archived')

    tag_name = settings.TAGS['phishing_autoclosed'] if ticket.category.name.lower() == 'phishing' else settings.TAGS['copyright_autoclosed']
    ticket.tags.add(Tag.objects.get(name=tag_name))
    ticket.save()

    database.log_action_on_ticket(
        ticket=ticket,
        action='change_status',
        previous_value=ticket.previousStatus,
        new_value=ticket.status,
        close_reason=ticket.resolution.codename
    )
    database.log_action_on_ticket(
        ticket=ticket,
        action='add_tag',
        tag_name=tag_name
    )


def _get_ip_for_action(ticket):
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


def _send_email(ticket, email, codename, lang='EN'):
    """
        Wrapper to send email
    """
    common.send_email(
        ticket,
        [email],
        codename,
        lang=lang,
    )


def mass_contact(ip_address=None, category=None, campaign_name=None, email_subject=None, email_body=None, user_id=None):
    """
        Try to identify customer based on `ip_address`, creates Cerberus ticket
        then send email to customer and finally close ticket.

        The use case is: a trusted provider sent you a list of vulnerable DNS servers (DrDOS amp) for example.
        To prevent abuse on your network, you notify customer of this vulnerability.

        :param str ip_address: The IP address
        :param str category: The category of the abuse
        :param str campaign_name: The name if the "mass-conctact" campaign
        :param str email_subject: The subject of the email to send to defendant
        :param str email_body: The body of the email to send to defendant
        :param int user_id: The id of the Cerberus `abuse.models.User` who created the campaign
    """
    # Check params
    _, _, _, values = inspect.getargvalues(inspect.currentframe())
    if not all(values.values()):
        Logger.error(unicode('invalid parameters submitted %s' % str(values)))
        return

    try:
        validate_ipv46_address(ip_address)
    except (TypeError, ValidationError):
        Logger.error(unicode('invalid ip addresses submitted'))
        return

    # Get Django model objects
    try:
        category = Category.objects.get(name=category)
        user = User.objects.get(id=user_id)
    except (AttributeError, ObjectDoesNotExist, TypeError):
        Logger.error(unicode('invalid user or category'))
        return

    # Identify service for ip_address
    try:
        services = ImplementationFactory.instance.get_singleton_of('CustomerDaoBase').get_services_from_items(ips=[ip_address])
        schema.valid_adapter_response('CustomerDaoBase', 'get_services_from_items', services)
    except CustomerDaoException as ex:
        Logger.error(unicode('Exception while identifying defendants for ip %s -> %s ' % (ip_address, str(ex))))
        raise CustomerDaoException(ex)

    # Create report/ticket
    if services:
        Logger.debug(unicode('creating report/ticket for ip address %s' % (ip_address)))
        with pglocks.advisory_lock('cerberus_lock'):
            __create_contact_tickets(services, campaign_name, ip_address, category, email_subject, email_body, user)
        return True
    else:
        Logger.debug(unicode('no service found for ip address %s' % (ip_address)))
        return False


@transaction.atomic
def __create_contact_tickets(services, campaign_name, ip_address, category, email_subject, email_body, user):

    # Create fake report
    report_subject = 'Campaign %s for ip %s' % (campaign_name, ip_address)
    report_body = 'Campaign: %s\nIP Address: %s\n' % (campaign_name, ip_address)
    filename = hashlib.sha256(report_body.encode('utf-8')).hexdigest()
    __save_email(filename, report_body)

    for data in services:  # For identified (service, defendant, items) tuple

        actions = []

        # Create report
        report = Report.objects.create(**{
            'provider': database.get_or_create_provider('mass_contact'),
            'receivedDate': datetime.now(),
            'subject': report_subject,
            'body': report_body,
            'category': category,
            'filename': filename,
            'status': 'Archived',
            'defendant': database.get_or_create_defendant(data['defendant']),
            'service': database.get_or_create_service(data['service']),
        })
        database.log_new_report(report)

        # Create item
        item_dict = {'itemType': 'IP', 'report_id': report.id, 'rawItem': ip_address}
        item_dict.update(utils.get_reverses_for_item(ip_address, nature='IP'))
        ReportItem.objects.create(**item_dict)

        # Create ticket
        ticket = database.create_ticket(
            report.defendant,
            report.category,
            report.service,
            priority=report.provider.priority,
            attach_new=False,
        )
        database.add_mass_contact_tag(ticket, campaign_name)
        actions.append({'ticket': ticket, 'action': 'create_masscontact', 'campaign_name': campaign_name})
        actions.append({'ticket': ticket, 'action': 'change_treatedby', 'new_value': user.username})
        report.ticket = ticket
        report.save()
        Logger.debug(unicode(
            'ticket %d successfully created for (%s, %s)' % (ticket.id, report.defendant.customerId, report.service.name)
        ))

        # Send email to defendant
        __send_mass_contact_email(ticket, email_subject, email_body)
        actions.append({'ticket': ticket, 'action': 'send_email', 'email': report.defendant.details.email})

        # Close ticket/report
        ticket.resolution = Resolution.objects.get(codename=settings.CODENAMES['fixed_customer'])
        ticket.previousStatus = ticket.status
        ticket.status = 'Closed'
        ticket.save()
        actions.append({
            'ticket': ticket,
            'action': 'change_status',
            'previous_value': ticket.previousStatus,
            'new_value': ticket.status,
            'close_reason': ticket.resolution.codename
        })

        for action in actions:
            database.log_action_on_ticket(**action)


def __send_mass_contact_email(ticket, email_subject, email_body):

    template = loader.get_template_from_string(email_subject)
    context = Context({
        'publicId': ticket.publicId,
        'service': ticket.service.name.replace('.', '[.]'),
        'lang': ticket.defendant.details.lang,
    })
    subject = template.render(context)

    template = loader.get_template_from_string(email_body)
    context = Context({
        'publicId': ticket.publicId,
        'service': ticket.service.name.replace('.', '[.]'),
        'lang': ticket.defendant.details.lang,
    })
    body = template.render(context)

    ImplementationFactory.instance.get_singleton_of('MailerServiceBase').send_email(
        ticket,
        ticket.defendant.details.email,
        subject,
        body,
        'MassContact',
    )


def check_mass_contact_result(result_campaign_id=None, jobs=None):
    """
        Check "mass-contact" campaign jobs's result

        :param int result_campaign_id: The id of the `abuse.models.MassContactResult`
        :param list jobs: The list of associated Python-Rq jobs id
    """
    # Check params
    _, _, _, values = inspect.getargvalues(inspect.currentframe())
    if not all(values.values()) or not isinstance(jobs, list):
        Logger.error(unicode('invalid parameters submitted %s' % str(values)))
        return

    if not isinstance(result_campaign_id, MassContactResult):
        try:
            campaign_result = MassContactResult.objects.get(id=result_campaign_id)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            Logger.error(unicode('MassContactResult %d cannot be found in DB. Skipping...' % (result_campaign_id)))
            return

    result = []
    for job_id in jobs:
        job = utils.queue.fetch_job(job_id)
        if not job:
            continue
        while job.status.lower() == 'queued':
            sleep(0.5)
        result.append(job.result)

    count = Counter(result)
    campaign_result.state = 'Done'
    campaign_result.matchingCount = count[True]
    campaign_result.notMatchingCount = count[False]
    campaign_result.failedCount = count[None]
    campaign_result.save()
    Logger.info(unicode('MassContact campaign %d finished' % (campaign_result.campaign.id)))


def __save_email(filename, email):
    """
        Push email storage service

        :param str filename: The filename of the email
        :param str email: The content of the email
    """
    with ImplementationFactory.instance.get_instance_of('StorageServiceBase', settings.GENERAL_CONFIG['email_storage_dir']) as cnx:
        cnx.write(filename, email.encode('utf-8'))
        Logger.info(unicode('Email %s pushed to Storage Service' % (filename)))


def create_ticket_from_phishtocheck(report=None, user=None):
    """
        Create/attach report to ticket + block_url + mail to defendant + email to provider

        :param int report: The id of the `abuse.models.Report`
        :param int user: The id of the `abuse.models.User`
    """
    if not isinstance(report, Report):
        try:
            report = Report.objects.get(id=report)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            Logger.error(unicode('Report %d cannot be found in DB. Skipping...' % (report)))
            return

    if not isinstance(user, User):
        try:
            user = User.objects.get(id=user)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            Logger.error(unicode('User %d cannot be found in DB. Skipping...' % (user)))
            return

    # Create/attach to ticket
    ticket = database.search_ticket(report.defendant, report.category, report.service)
    new_ticket = False

    if not ticket:
        ticket = database.create_ticket(report.defendant, report.category, report.service, priority=report.provider.priority)
        new_ticket = True
        utils.scheduler.enqueue_in(
            timedelta(seconds=settings.GENERAL_CONFIG['phishing']['wait']),
            'ticket.timeout',
            ticket_id=ticket.id,
            timeout=3600,
        )

    common.get_temp_proofs(ticket, only_urls=True)

    report.ticket = ticket
    report.status = 'Attached'
    report.save()
    database.log_action_on_ticket(
        ticket=ticket,
        action='attach_report',
        report=report,
        new_ticket=new_ticket
    )
    database.log_action_on_ticket(
        ticket=ticket,
        action='validate_phishtocheck',
        user=user,
        report=report
    )

    # Sending email to provider
    if settings.TAGS['no_autoack'] not in report.provider.tags.all().values_list('name', flat=True):

        common.send_email(
            ticket,
            [report.provider.email],
            settings.CODENAMES['ack_received'],
            acknowledged_report_id=report.id,
        )

    utils.queue.enqueue('phishing.block_url_and_mail', ticket_id=ticket.id, report_id=report.id, timeout=3600)
    return ticket


def cancel_rq_scheduler_jobs(ticket_id=None):
    """
        Cancel all rq scheduler jobs for given `abuse.models.Ticket`

        :param int ticket_id: The id of the `abuse.models.Ticket`
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
        Logger.error(unicode('Ticket %d cannot be found in DB. Skipping...' % (ticket)))
        return

    for job in utils.scheduler.get_jobs():
        if job.func_name in WORKER_TICKET_FUNC and job.kwargs['ticket_id'] == ticket.id:
            utils.scheduler.cancel(job.id)


def follow_the_sun():
    """
        Set tickets to alarm when user is away
    """
    now = int(time())
    where = [~Q(status='Open'), ~Q(status='Reopened'), ~Q(status='Paused'), ~Q(status='Closed')]
    where = reduce(operator.and_, where)

    for user in User.objects.filter(~Q(username=BOT_USER.username)):
        if now > mktime((user.last_login + timedelta(hours=24)).timetuple()):
            Logger.debug(
                unicode('user %s logged out, set alarm to True' % (user.username)),
                extra={
                    'user': user.username,
                }
            )
            user.ticketUser.filter(where).update(alarm=True)
        else:
            Logger.debug(
                str('user %s logged in, set alarm to False' % (user.username)),
                extra={
                    'user': user.username,
                }
            )
            user.ticketUser.filter(where).update(alarm=False)


def update_waiting():
    """
        Update waiting answer tickets
    """
    now = int(time())
    for ticket in Ticket.objects.filter(status=WAITING):
        try:
            if now > int(mktime(ticket.snoozeStart.timetuple()) + ticket.snoozeDuration):
                Logger.debug(
                    unicode('Updating status for ticket %s ' % (ticket.id)),
                    extra={
                        'ticket': ticket.id,
                    }
                )
                _check_auto_unassignation(ticket)
                ticket.status = ALARM
                ticket.snoozeStart = None
                ticket.snoozeDuration = None
                ticket.previousStatus = WAITING
                ticket.reportTicket.all().update(status='Attached')
                ticket.save()
                database.log_action_on_ticket(
                    ticket=ticket,
                    action='change_status',
                    previous_value=ticket.previousStatus,
                    new_value=ticket.status
                )

        except (AttributeError, ValueError) as ex:
            Logger.debug(unicode('Error while updating ticket %d : %s' % (ticket.id, ex)))


def _check_auto_unassignation(ticket):

    history = ticket.ticketHistory.filter(actionType='ChangeStatus').order_by('-date').values_list('ticketStatus', flat=True)[:3]
    try:
        unassigned_on_multiple_alarm = ticket.treatedBy.operator.role.modelsAuthorizations['ticket']['unassignedOnMultipleAlarm']
        if unassigned_on_multiple_alarm and len(history) == 3 and all([STATUS_SEQUENCE[i] == history[i] for i in xrange(3)]):
            database.log_action_on_ticket(
                ticket=ticket,
                action='change_treatedby',
                previous_value=ticket.treatedBy
            )
            database.log_action_on_ticket(
                ticket=ticket,
                action='update_property',
                property='escalated',
                previous_value=ticket.escalated,
                new_value=True,
            )
            ticket.treatedBy = None
            ticket.escalated = True
            Logger.debug(unicode('Unassigning ticket %d because of operator role configuration' % (ticket.id)))
    except (AttributeError, KeyError, ObjectDoesNotExist, ValueError):
        pass


def update_paused():
    """
        Update paused tickets
    """
    now = int(time())
    for ticket in Ticket.objects.filter(status=PAUSED):
        try:
            if now > int(mktime(ticket.pauseStart.timetuple()) + ticket.pauseDuration):
                Logger.debug(
                    str('Updating status for ticket %s ' % (ticket.id)),
                    extra={
                        'ticket': ticket.id,
                    }
                )
                if ticket.previousStatus == WAITING and ticket.snoozeDuration and ticket.snoozeStart:
                    ticket.snoozeDuration = ticket.snoozeDuration + (datetime.now() - ticket.pauseStart).seconds

                ticket.status = ticket.previousStatus
                ticket.pauseStart = None
                ticket.pauseDuration = None
                ticket.previousStatus = PAUSED
                ticket.save()
                database.log_action_on_ticket(
                    ticket=ticket,
                    action='change_status',
                    previous_value=ticket.previousStatus,
                    new_value=ticket.status
                )

        except (AttributeError, ValueError) as ex:
            Logger.debug(unicode('Error while updating ticket %d : %s' % (ticket.id, ex)))
