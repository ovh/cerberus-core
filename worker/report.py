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
    Report functions for worker
"""
import hashlib
from collections import Counter
from datetime import datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import ObjectDoesNotExist, Q

import database
import phishing
from abuse.models import (AttachedDocument, Report, ReportItem, Resolution,
                          Proof, ReportThreshold, Ticket, Defendant, Service)
from adapters.dao.customer.abstract import CustomerDaoException
from adapters.services.mailer.abstract import MailerServiceException
from adapters.services.search.abstract import SearchServiceException
from adapters.services.storage.abstract import StorageServiceException
from factory.factory import ImplementationFactory
from parsing import regexp
from parsing.parser import EmailParser
from utils import pglocks, schema, utils
from worker import Logger

Parser = EmailParser()


def create_from_email(email_content=None, filename=None, lang='EN', send_ack=False):
    """ Create Cerberus report(s) based on email content

        If send_ack is True and report is attached to a ticket,
        then an acknowledgement is sent to the email provider.

        :param str email_content: The raw email content
        :param str filename: The name of the raw email file
        :param str lang: Langage to use if send_ack is True
        :param bool send_ack: If an acknowledgment have to be sent to provider
        :raises CustomerDaoException: if exception while identifying defendants from items
        :raises MailerServiceException: if exception while updating ticket's emails
        :raises StorageServiceException: if exception while accessing storage

    """
    # This function use a lock/commit_on_succes on db when creating reports
    #
    # Huge blocks of code are under transaction because it's important to
    # rollback if ANYTHING goes wrong in the report creation workflow.
    #
    # But concurrent transactions (with multiple workers), on defendant/service creation
    # for example, can result in unconsistent data. So a pg_lock is used.

    if not email_content:
        Logger.error(unicode('Missing email content'))
        return

    if not filename:  # Worker have to push email to Storage Service
        filename = hashlib.sha256(email_content).hexdigest()
        __save_email(filename, email_content)

    # Parse email content
    abuse_report = Parser.parse(email_content)

    # Check if it's an answer to a ticket
    ticket = __get_ticket_if_answer(abuse_report, filename)
    if ticket:  # OK it's an anwser, updating ticket and exiting
        try:
            __update_ticket_if_answer(ticket, abuse_report, filename)
            return
        except MailerServiceException as ex:
            raise MailerServiceException(ex)

    # Check if items are linked to customer and get corresponding services
    try:
        services = ImplementationFactory.instance.get_singleton_of('CustomerDaoBase').get_services_from_items(
            urls=abuse_report.urls,
            ips=abuse_report.ips,
            fqdn=abuse_report.fqdn
        )
        schema.valid_adapter_response('CustomerDaoBase', 'get_services_from_items', services)
    except CustomerDaoException as ex:
        Logger.error(unicode('Exception while identifying defendants from items for mail %s -> %s ' % (filename, str(ex))))
        raise CustomerDaoException(ex)

    # Create report(s) with identified services
    try:
        if not services:
            created_reports = [__create_without_services(abuse_report, filename)]
        else:
            with pglocks.advisory_lock('cerberus_lock'):
                created_reports = __create_with_services(abuse_report, filename, services)
    except StorageServiceException as ex:
        Logger.error(unicode('Exception while creating report(s) for mail %s -> %s' % (filename, str(ex))))
        raise StorageServiceException(ex)

    # Upload attachments
    if abuse_report.attachments:
        for report in created_reports:
            save_attachments(report, abuse_report.attachments)

    # Send acknowledgement to provider (only if send_ack = True and report is attached to a ticket)
    for report in created_reports:
        if send_ack and report.ticket:
            try:
                __send_ack(report, lang=lang)
            except MailerServiceException as ex:
                raise MailerServiceException(ex)

    # Index to SearchService
    if ImplementationFactory.instance.is_implemented('SearchServiceBase'):
        __index_report_to_searchservice(abuse_report, filename, [rep.id for rep in created_reports])

    Logger.info(unicode('All done successfully for email %s' % (filename)))


@transaction.atomic
def __create_without_services(abuse_report, filename, create_if_trusted=True):
    """
        Create report in Cerberus

        :param `worker.parsing.parser.ParsedEmail` abuse_report: The `worker.parsing.parser.ParsedEmail`
        :param str filename: The filename of the email
        :rtype: `abuse.models.Report`
        :returns: The Cerberus `abuse.models.Report`
    """
    report = Report.objects.create(**{
        'provider': database.get_or_create_provider(abuse_report.provider),
        'receivedDate': datetime.fromtimestamp(abuse_report.date),
        'subject': abuse_report.subject,
        'body': abuse_report.body,
        'category': database.get_category(abuse_report.category),
        'filename': filename,
        'status': 'New',
    })

    __add_report_tags(report, abuse_report.recipients)
    autoarchive, _, _ = __get_attributes_based_on_tags(report, abuse_report.recipients)
    database.log_new_report(report)

    # If report is not attached within 30 days -> archived
    utils.scheduler.enqueue_in(
        timedelta(days=settings.GENERAL_CONFIG['report_timeout']),
        'report.archive_if_timeout',
        report_id=report.id
    )

    if autoarchive:
        report.status = 'Archived'
    else:
        if abuse_report.trusted and create_if_trusted:
            ticket = database.create_ticket(report.defendant, report.category, report.service, priority=report.provider.priority)
            action = 'create this ticket with report %d from %s (%s ...)'
            database.log_action_on_ticket(ticket, action % (report.id, report.provider.email, report.subject[:30]))
            report.ticket = ticket
            report.status = 'Attached'

    report.save()
    return report


@transaction.atomic
def __create_with_services(abuse_report, filename, services):
    """
        Create report(s), ticket(s), item(s), defendant(s), service(s), attachment(s) in Cerberus

        :param `ParsedEmail` abuse_report: The `ParsedEmail`
        :param str filename: The filename of the email
        :param dict services: The identified service(s) (see adapters/dao/customer/abstract.py)
        :rtype: list
        :returns: The list of Cerberus `abuse.models.Report` created
    """
    created_reports = []

    for data in services:  # For identified (service, defendant, items) tuple

        report = __create_without_services(abuse_report, filename, create_if_trusted=False)
        created_reports.append(report)
        report.defendant = database.get_or_create_defendant(data['defendant'])
        report.service = database.get_or_create_service(data['service'])
        report.save()

        if report.status == 'Archived':  # because autoarchive tag
            continue

        _, attach_only, no_phishtocheck = __get_attributes_based_on_tags(report, abuse_report.recipients)
        __insert_items(report.id, data['items'])

        # The provider or the way we received the report
        trusted = True if report.provider.trusted or abuse_report.trusted else False

        # Looking for existing open ticket for same (service, defendant, category)
        if all((report.defendant, report.category, report.service)):
            msg = 'Looking for opened ticket for (%s, %s, %s)'
            Logger.debug(unicode(msg % (report.defendant.customerId, report.category.name, report.service.name)))
            ticket = database.search_ticket(report.defendant, report.category, report.service)

        is_there_some_urls = report.reportItemRelatedReport.filter(itemType='URL').exists()

        # Phishing specific workflow
        if report.category.name.lower() == 'phishing' and is_there_some_urls:
            Logger.debug(unicode('New phishing report %d' % (report.id)))
            is_workflow_applied = __do_phishing_workflow(report, no_phishtocheck)
            if is_workflow_applied:
                continue

        # ACNS specific workflow
        if (trusted and report.category.name.lower() == 'copyright' and
                any([pattern in report.body for pattern in settings.GENERAL_CONFIG['acns_patterns']])):
            Logger.debug(unicode('New ACNS/copyright report %d, applying specific workflow' % (report.id)))
            __do_copyright_acns_workflow(report)
            continue

        # If attach report only and no ticket found, continue
        ticket = None
        if not ticket and attach_only:
            report.status = 'Archived'
            report.save()
            continue

        # Create ticket if trusted
        action = None
        if not ticket and trusted:
            ticket = database.create_ticket(report.defendant, report.category, report.service, priority=report.provider.priority)
            action = 'create this ticket with report %d from %s (%s ...)'

        # If attached to new or exising
        if ticket:

            # Block phishing url signaled by trusted provider
            if report.provider.apiKey and report.category.name.lower() == 'phishing' and is_there_some_urls:
                phishing.block_url_and_mail(ticket_id=ticket.id, report_id=report.id)

            report.ticket = Ticket.objects.get(id=ticket.id)
            report.status = 'Attached'
            report.save()
            action = action if action else 'attach report %d from %s (%s ...) to this ticket'
            database.log_action_on_ticket(ticket, action % (report.id, report.provider.email, report.subject[:30]))

    return created_reports


def __index_report_to_searchservice(parsed_email, filename, reports_id):
    """ Index a report to the SearchService
    """
    try:
        Logger.debug(unicode('Pushing email %s document to SearchService' % (filename)))
        ImplementationFactory.instance.get_singleton_of('SearchServiceBase').index_email(
            parsed_email,
            filename,
            reports_id
        )
    except SearchServiceException as ex:
        # Not fatal => don't stop current routine
        Logger.error(unicode('Unable to index mail %s in SearchService -> %s' % (filename, ex)))


def __send_ack(report, lang=None):
    """ Send acknoledgement to provider

        :param `abuse.models.Report` report: A `abuse.models.Report` instance
        :param string lang: The langage to use
    """
    if settings.TAGS['no_autoack'] not in report.provider.tags.all().values_list('name', flat=True):
        prefetched_email = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').prefetch_email_from_template(
            report.ticket,
            settings.CODENAMES['ack_received'],
            lang=lang,
            acknowledged_report=report.id,
        )
        ImplementationFactory.instance.get_singleton_of('MailerServiceBase').send_email(
            report.ticket,
            report.provider.email,
            prefetched_email.subject,
            prefetched_email.body
        )
        database.log_action_on_ticket(report.ticket, 'send an email to %s' % (report.provider.email))

    report.ticket = Ticket.objects.get(id=report.ticket.id)
    report.save()


def __insert_items(report_id, items):
    """ Insert report's items for to database

        :param int report_id: The id of the report
        :param dict items: A dict of list containing the items
    """
    for item_type in ['urls', 'ips', 'fqdn']:
        nature = item_type.replace('s', '').upper()
        if items.get(item_type):
            for item in items[item_type]:
                item_dict = {
                    'itemType': nature,
                    'report_id': report_id,
                    'rawItem': item[:4000],
                }
                item_dict.update(utils.get_reverses_for_item(item, nature=nature))
                ReportItem.objects.create(**item_dict)


def save_attachments(report, attachments):
    """ Upload email attachments to StorageService and keep a reference in Cerberus

        :param `abuse.models.Report` report: A `abuse.models.Report` instance
        :param list attachments: A list of dict {'filename': 'test.pdf', 'data': '...', 'type': 'application/pdf'}
    """
    for attachment in attachments:
        storage_filename = report.filename + '-attach-'
        storage_filename = storage_filename.encode('utf-8')
        storage_filename = storage_filename + attachment['filename']

        AttachedDocument.objects.create(
            report=report,
            name=attachment['filename'],
            filename=storage_filename,
            filetype=attachment['type'],
        )

        with ImplementationFactory.instance.get_instance_of('StorageServiceBase', settings.GENERAL_CONFIG['email_storage_dir']) as cnx:
            cnx.write(storage_filename, attachment['data'])


def __save_email(filename, email):
    """
        Push email storage service

        :param str filename: The filename of the email
        :param str email: The content of the email
    """
    with ImplementationFactory.instance.get_instance_of('StorageServiceBase', settings.GENERAL_CONFIG['email_storage_dir']) as cnx:
        cnx.write(filename, email)
        Logger.info(unicode('Email %s pushed to Storage Service' % (filename)))


def __add_report_tags(report, recipients):
    """
        Add tags to report based on provider, subject etc ...

        :param `abuse.models.Report` report: A `abuse.models.Report` instance
        :param list recipients: The list of recipients
    """
    tags = database.get_tags(report.provider, recipients, report.subject, report.body)

    for tag in tags:
        if tag.tagType == 'Report':
            report.tags.add(tag)


def __get_attributes_based_on_tags(report, recipients):
    """
        Get specific attributes based on provider's tags

        :param `abuse.models.Report` report: A `abuse.models.Report` instance
        :param list recipients: The list of recipients
        :rtype: tuple
        :returns: tuple of bool (autoarchive, attach_only, no_phishtocheck)
    """
    autoarchive = attach_only = no_phishtocheck = False
    tags = database.get_tags(report.provider, recipients, report.subject, report.body)

    for tag in tags:
        if tag.tagType == 'Provider':
            if tag.name == settings.TAGS['autoarchive']:
                autoarchive = True
            if tag.name == settings.TAGS['attach_only']:
                attach_only = True
            if tag.name == settings.TAGS['no_phishtocheck']:
                no_phishtocheck = True

    return autoarchive, attach_only, no_phishtocheck


def __do_phishing_workflow(report, no_phishtocheck):
    """
        Apply specific workflow for phishing report
    """
    all_down = False
    Logger.debug(unicode('Phishing report %d' % (report.id)))
    all_down = phishing.check_if_all_down(report=report)

    # Archived report immediatly
    if all_down:
        phishing.close_because_all_down(report=report)
        return True

    if no_phishtocheck:
        # Just pass
        return True

    # Report has to be manually checked
    if not report.provider.trusted:
        report.status = 'PhishToCheck'
        report.save()
        utils.push_notification({
            'type': 'new phishToCheck',
            'id': report.id,
            'message': 'New PhishToCheck report %d' % (report.id),
        })
        return True

    return False


def __do_copyright_acns_workflow(report):
    """
        Apply specific workflow for copyright-acns report
    """
    # Create ticket
    ticket = database.create_ticket(report.defendant, report.category, report.service, attach_new=False)
    database.log_action_on_ticket(
        ticket,
        'create this ticket with report %d from %s (%s ...)' % (report.id, report.provider.email, report.subject[:30])
    )

    # Add proof
    Proof.objects.create(
        content=regexp.ACNS_PROOF.search(report.body).group(),
        ticket=ticket,
    )

    # Send emails to provider/defendant (template, email, lang)
    templates = [
        (settings.CODENAMES['ack_received'], report.provider.email, 'EN'),
        (settings.CODENAMES['first_alert'], report.defendant.details.email, report.defendant.details.lang),
    ]
    for codename, email, lang in templates:
        prefetched_email = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').prefetch_email_from_template(
            ticket,
            codename,
            lang=lang,
            acknowledged_report=report.id,
        )
        ImplementationFactory.instance.get_singleton_of('MailerServiceBase').send_email(
            ticket,
            email,
            prefetched_email.subject,
            prefetched_email.body
        )
        database.log_action_on_ticket(ticket, 'send an email to %s' % (email))

    # Close ticket
    ImplementationFactory.instance.get_singleton_of('MailerServiceBase').close_thread(ticket)
    resolution = Resolution.objects.get(codename=settings.CODENAMES['forward_acns'])
    ticket.resolution = resolution
    ticket.previousStatus = ticket.status
    ticket.status = 'Closed'
    ticket.update = False
    ticket.save()
    database.log_action_on_ticket(
        ticket,
        'change status from %s to %s, reason : %s' % (ticket.previousStatus, ticket.status, resolution.codename)
    )
    report.ticket = ticket
    report.status = 'Archived'
    report.save()


def __get_ticket_if_answer(abuse_report, filename):
    """ Check if the email is a ticket's answer

        :param `worker.parsing.parser.ParsedEmail` abuse_report: The ParsedEmail
        :return: the corresponding ticket
        :rtype: `abuse.models.Ticket`
    """
    Logger.debug(
        unicode('New email from %s' % (abuse_report.provider)),
        extra={
            'from': abuse_report.provider,
            'action': 'new email',
            'hash': filename,
        }
    )

    ticket = None
    if all((abuse_report.provider, abuse_report.recipients, abuse_report.subject, abuse_report.body)):
        ticket = __identify_ticket_from_meta(
            abuse_report.provider,
            abuse_report.recipients,
            abuse_report.subject,
        )
    return ticket


def __identify_ticket_from_meta(provider, recipients, subject):
    """
        Try to identify an answer to a Cerberus ticket with email meta

    """
    if not all((provider, recipients, subject)):
        return None

    ticket = None
    # Trying with recipient
    for recipient in recipients:
        search = regexp.RECIPIENT.search(str(recipient).lower())
        if search is not None:
            public_id = str(search.group(1)).lower()
            try:
                ticket = Ticket.objects.get(publicId__iexact=public_id)
                hsh = hashlib.sha512(str(ticket.id)).hexdigest()[-4:]
            except (IndexError, TypeError, ValueError, ObjectDoesNotExist):
                continue

            # Checking hash
            if str(search.group(2)) == str(hsh):
                break
    return ticket


def __update_ticket_if_answer(ticket, abuse_report, filename):
    """
        If the email is an answer to a cerberus ticket:

        - update ticket status
        - append response to ticket's email thread
        - save attachments

        :param `abuse.models.Ticket` ticket: A Cerberus `abuse.models.Ticket` instance
        :param `worker.parsing.parser.ParsedEmail` abuse_report: The ParsedEmail
        :param str filename: The filename of the email
    """
    Logger.debug(
        unicode('New answer from %s for ticket %s' % (abuse_report.provider, ticket.id)),
        extra={
            'from': abuse_report.provider,
            'action': 'new answer',
            'hash': filename,
            'ticket': ticket.id,
        }
    )
    actions = ['received an email from %s' % (abuse_report.provider)]

    if not abuse_report.ack:

        ticket.previousStatus = ticket.status
        ticket.status = 'Answered'
        ticket.snoozeStart = None
        ticket.snoozeDuration = None
        ticket.reportTicket.all().update(status='Attached')
        ticket.save()
        actions.append('change status from %s to %s' % (ticket.previousStatus, ticket.status))

    for action in actions:
        database.log_action_on_ticket(ticket, action)

    ImplementationFactory.instance.get_singleton_of('MailerServiceBase').attach_external_answer(
        ticket,
        abuse_report.provider,
        abuse_report.subject,
        abuse_report.body,
    )

    if abuse_report.attachments:
        save_attachments(
            ticket.reportTicket.all()[0],
            abuse_report.attachments,
        )


def archive_if_timeout(report_id=None):
    """
        Archived report if not attached

        :param int report_id: The report id
    """
    if not report_id:
        Logger.error(unicode('Invalid parameters submitted [report_id=%d]' % (report_id)))
        return

    try:
        report = Report.objects.get(id=report_id)
    except (ObjectDoesNotExist, ValueError):
        Logger.error(unicode('Report %d cannot be found in DB. Skipping...' % (report_id)))
        return

    if report.status != 'New':
        Logger.error(unicode('Report %d not New, status : %s , Skipping ...' % (report_id, report.status)))
        return

    report.ticket = None
    report.status = 'Archived'
    report.save()
    Logger.info(unicode('Report %d successfully archived' % (report_id)))


def create_ticket_with_threshold():
    """
        Automatically creates ticket if there are more than `abuse.models.ReportThreshold.threshold`
        new reports created during `abuse.models.ReportThreshold.interval` (days) for same (category/defendant/service)
    """
    log_msg = 'threshold : Checking report threshold for category %s, threshold %d, interval %d days'

    for thres in ReportThreshold.objects.all():
        Logger.info(unicode(log_msg % (thres.category.name, thres.threshold, thres.interval)))
        reports = __get_threshold_reports(thres.category, thres.interval)
        reports = Counter(reports)
        for data, count in reports.iteritems():
            nb_tickets = Ticket.objects.filter(
                ~Q(status='Closed'),
                defendant__customerId=data[0],
                service__name=data[1]
            ).count()
            if count >= thres.threshold and not nb_tickets:
                ticket = __create_threshold_ticket(data, thres)
                Logger.info(unicode('threshold: tuple %s match, ticket %s has been created' % (str(data), ticket.id)))


def __get_threshold_reports(category, delta):

    reports = Report.objects.filter(
        ~Q(defendant=None),
        ~Q(service=None),
        category=category,
        status='New',
        receivedDate__gte=datetime.now() - timedelta(days=delta),
    ).values_list(
        'defendant__customerId',
        'service__name'
    )
    return reports


def __create_threshold_ticket(data, thres):

    service = Service.objects.filter(name=data[1]).last()
    defendant = Defendant.objects.filter(customerId=data[0]).last()
    ticket = database.create_ticket(defendant, thres.category, service)
    database.log_action_on_ticket(
        ticket,
        'create this ticket with threshold (more than %s reports received in %s days)' % (thres.threshold, thres.interval)
    )
    return ticket
