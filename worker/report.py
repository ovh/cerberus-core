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
from datetime import datetime

from django.conf import settings
from django.db import transaction
from django.db.models import ObjectDoesNotExist

import common
import database
from abuse.models import (AttachedDocument, Report,
                          ReportItem, User, BusinessRules,
                          BusinessRulesHistory)
from adapters.services.search.abstract import SearchServiceException
from factory.implementation import ImplementationFactory as implementations
from parsing.parser import EmailParser
from utils import pglocks, schema, utils

try:
    from worker.workflows.actions import CDNRequestActions, EmailReplyActions, ReportActions
    from worker.workflows.engine import run
    from worker.workflows.variables import CDNRequestVariables, EmailReplyVariables, ReportVariables
except ImportError:
    from .workflows.actions import CDNRequestActions, EmailReplyActions, ReportActions
    from .workflows.engine import run
    from .workflows.variables import CDNRequestVariables, EmailReplyVariables, ReportVariables

from worker import Logger

Parser = EmailParser()


def create_from_email(email_content=None, filename=None, ack_lang='EN'):
    """
        Create Cerberus report(s) based on email content

        :param str email_content: The raw email content
        :param str filename: The name of the raw email file
        :param str ack_lang: Langage to use
                         if `worker.workflows.actions.report.send_provider_ack` is triggered
        :raises `adapters.dao.customer.abstract.CustomerDaoException`:
                if exception while identifying defendants from items
        :raises `adapters.services.mailer.abstract.MailerServiceException:
                if exception while updating ticket's emails
        :raises `adapters.services.storage.abstract.StorageServiceException:
                if exception while accessing storage
    """
    # This function use a lock/commit_on_succes on db when creating reports
    #
    # Huge blocks of code are under transaction because it's important to
    # rollback if ANYTHING goes wrong in the report creation workflow.
    #
    # Concurrent transactions (with multiple workers), on defendant/service creation
    # can result in unconsistent data, So a pg_lock is used.
    #
    # `abuse.models.Defendant` and `abuse.models.Service` HAVE to be unique.

    if not filename:  # Worker have to push email to Storage Service
        filename = hashlib.sha256(email_content).hexdigest()
        common.save_email(filename, email_content)

    # Parse email content
    abuse_report = Parser.parse(email_content)
    Logger.debug(
        unicode('New email from %s' % (abuse_report.provider)),
        extra={
            'from': abuse_report.provider,
            'action': 'new email'
        }
    )

    # Check if provider is not blacklisted
    if abuse_report.provider in settings.PARSING['providers_to_ignore']:
        Logger.error(unicode('Provider %s is blacklisted, skipping ...' % (abuse_report.provider)))
        return

    # Check if it's an answer to a ticket(s)
    tickets = implementations.instance.get_singleton_of(
        'MailerServiceBase'
    ).is_email_ticket_answer(abuse_report)
    if tickets:
        for ticket, category, recipient in tickets:
            if all((ticket, category, recipient)) and not ticket.locked:  # it's an ticket anwser
                _update_ticket_if_answer(ticket, category, recipient, abuse_report, filename)
        return

    # Check if items are linked to customer and get corresponding services
    services = implementations.instance.get_singleton_of(
        'CustomerDaoBase'
    ).get_services_from_items(
        urls=abuse_report.urls,
        ips=abuse_report.ips,
        fqdn=abuse_report.fqdn
    )
    schema.valid_adapter_response('CustomerDaoBase', 'get_services_from_items', services)

    # Create report(s) with identified services
    if not services:
        created_reports = [_create_without_services(abuse_report, filename, ack_lang=ack_lang)]
    else:
        with pglocks.advisory_lock('cerberus_lock'):
            _create_defendants_and_services(services)
        created_reports = _create_with_services(abuse_report, filename, services, ack_lang=ack_lang)

    # Upload attachments
    if abuse_report.attachments:
        _save_attachments(filename, abuse_report.attachments, reports=created_reports)

    # Index to SearchService
    if implementations.instance.is_implemented('SearchServiceBase'):
        _index_report_to_searchservice(abuse_report, filename, [rep.id for rep in created_reports])

    Logger.info(unicode('All done successfully for email %s' % (filename)))


def _create_defendants_and_services(services):

    for data in services:  # For identified (service, defendant, items) tuple

        data['defendant'] = database.get_or_create_defendant(data['defendant'])
        data['service'] = database.get_or_create_service(data['service'])


@transaction.atomic
def _create_without_services(abuse_report, filename, ack_lang='EN', apply_rules=True):
    """
        Create report in Cerberus

        :param `worker.parsing.parser.ParsedEmail` abuse_report:
            The `worker.parsing.parser.ParsedEmail`
        :param str filename: The filename of the email
        :param str ack_lang: Langage to use for report acknowledgement
        :param bool apply_rules: Run rules or not
        :rtype: `abuse.models.Report`
        :return: The Cerberus `abuse.models.Report`
    """
    provider = database.get_or_create_provider(abuse_report.provider)

    report = Report.objects.create(**{
        'provider': provider,
        'receivedDate': datetime.fromtimestamp(abuse_report.date),
        'subject': abuse_report.subject,
        'body': abuse_report.body,
        'category': database.get_category(abuse_report.category),
        'filename': filename,
        'status': 'New',
    })

    _add_report_tags(report, abuse_report.recipients)
    database.log_new_report(report)

    if apply_rules:
        _apply_business_rules(
            parsed_email=abuse_report,
            report=report,
            rules_type='Report',
            ack_lang=ack_lang
        )

    return report


@transaction.atomic
def _create_with_services(abuse_report, filename, services, ack_lang='EN'):
    """
        Create report(s), ticket(s), item(s), defendant(s), service(s), attachment(s) in Cerberus

        :param `ParsedEmail` abuse_report: The `ParsedEmail`
        :param str filename: The filename of the email
        :param dict services: The identified service(s) (see adapters/dao/customer/abstract.py)
        :param str ack_lang: Langage to use for report acknowledgement
        :rtype: list
        :return: The list of Cerberus `abuse.models.Report` created
    """
    created_reports = []

    for data in services:  # For identified (service, defendant, items) tuple

        report = _create_without_services(abuse_report, filename, apply_rules=False)
        created_reports.append(report)
        report.defendant = data['defendant']
        report.service = data['service']
        report.save()

        if report.status == 'Archived':  # because autoarchive tag
            continue

        _add_items(report.id, data['items'])

        # Looking for existing open ticket for same (service, defendant, category)
        ticket = None
        if all((report.defendant, report.category, report.service)):
            ticket = database.search_ticket(report.defendant, report.category, report.service)

        # Running rules
        rule_applied = _apply_business_rules(
            parsed_email=abuse_report,
            report=report,
            ticket=ticket,
            service=report.service,
            rules_type='Report',
            ack_lang=ack_lang
        )
        if rule_applied:
            continue

    return created_reports


def _apply_business_rules(**kwargs):

    if not BusinessRules.objects.count():
        return False

    report = kwargs.get('report')
    ticket = kwargs.get('ticket')
    defendant = report.defendant if report else ticket.defendant
    service = kwargs.get('service')

    rules, variables, actions = _get_business_rules_config(**kwargs)
    if not all((rules, variables, actions)):
        raise Exception("Unable to retrieve rules with params: {}".format(kwargs))

    for rule in rules:
        rule_applied = run(
            rule.config,
            defined_variables=variables,
            defined_actions=actions,
        )
        if rule_applied:
            BusinessRulesHistory.objects.create(
                businessRules=rule,
                defendant=defendant,
                report=report,
                ticket=ticket,
                service=service
            )
            if report:
                database.set_report_specificworkflow_tag(report, rule.name)
            Logger.debug(unicode('Workflow %s applied' % str(rule.name)))
            return True

    return False


def _get_business_rules_config(**kwargs):

    rules_type = kwargs['rules_type']
    parsed_email = kwargs.get('parsed_email')
    report = kwargs.get('report')
    ticket = kwargs.get('ticket')
    reply_recipient = kwargs.get('reply_recipient')
    cdn_domain_to_request = kwargs.get('domain_to_request')
    reply_category = kwargs.get('reply_category')
    trusted = kwargs.get('is_trusted')
    ack_lang = kwargs.get('ack_lang') or 'EN'

    variables = actions = None
    rules = BusinessRules.objects.filter(
        rulesType=rules_type
    ).order_by('orderId')

    if rules_type == 'Report':
        variables = ReportVariables(
            parsed_email,
            report,
            ticket,
            is_trusted=trusted
        )
        actions = ReportActions(
            report,
            ticket,
            ack_lang,
        )
    elif rules_type == 'EmailReply':
        variables = EmailReplyVariables(
            ticket,
            parsed_email,
            reply_recipient,
            reply_category
        )
        actions = EmailReplyActions(
            ticket,
            parsed_email,
            reply_recipient,
            reply_category
        )
    elif rules_type == 'CDNRequest':
        variables = CDNRequestVariables(
            cdn_domain_to_request
        )
        actions = CDNRequestActions(
            report,
            cdn_domain_to_request
        )

    return rules, variables, actions


def _index_report_to_searchservice(parsed_email, filename, reports_id):
    """
        Index a report to the SearchService
    """
    try:
        Logger.debug(unicode('Pushing email %s document to SearchService' % (filename)))
        implementations.instance.get_singleton_of('SearchServiceBase').index_email(
            parsed_email,
            filename,
            reports_id
        )
    except SearchServiceException as ex:
        # Not fatal => don't stop current routine
        Logger.error(unicode('Unable to index mail %s in SearchService -> %s' % (filename, ex)))


def _add_items(report_id, items):
    """
        Insert report's items for to database

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


def _save_attachments(filename, attachments, reports=None, tickets=None):
    """
        Upload email attachments to StorageService and keep a reference in Cerberus

        :param str filename: The filename of the email
        :param list attachments: The `worker.parsing.parsed.ParsedEmail.attachments` list :
            - [{'content': ..., 'content_type': ... ,'filename': ...}]
        :param list reports: A list of `abuse.models.Report` instance
        :param list tickets: A list of `abuse.models.Ticket` instance
    """
    for attachment in attachments[:20]:  # Slice 20 to avoid denial of service

        storage_filename = utils.get_attachment_storage_filename(
            hash_string=filename,
            filename=attachment['filename']
        )

        with implementations.instance.get_instance_of('StorageServiceBase', common.STORAGE_DIR) as cnx:
            cnx.write(storage_filename, attachment['content'])

        attachment_obj = AttachedDocument.objects.create(
            name=attachment['filename'],
            filename=storage_filename,
            filetype=attachment['content_type'],
        )

        if reports:
            for report in reports:
                report.attachments.add(attachment_obj)
        if tickets:
            for ticket in tickets:
                ticket.attachments.add(attachment_obj)


def _add_report_tags(report, recipients):
    """
        Add tags to report based on provider, subject etc ...

        :param `abuse.models.Report` report: A `abuse.models.Report` instance
        :param list recipients: The list of recipients
    """
    tags = database.get_tags(report.provider, recipients, report.subject, report.body)

    for tag in tags:
        if tag.tagType == 'Report':
            report.tags.add(tag)


def _update_ticket_if_answer(ticket, category, recipient, abuse_report, filename):
    """
        If the email is an answer to a cerberus ticket:

        - apply ticket's answer workflow if exists
        - save attachments

        :param `abuse.models.Ticket` ticket: A Cerberus `abuse.models.Ticket` instance
        :param str category: The category of the answer ('Defendant', 'Plaintiff' or 'Other)
        :param str recipient: The recipient of the answer
        :param `worker.parsing.parser.ParsedEmail` abuse_report: The ParsedEmail
        :param str filename: The filename of the email
    """
    Logger.debug(
        unicode('New %s answer from %s for ticket %s' % (category, abuse_report.provider, ticket.id)),
        extra={
            'from': abuse_report.provider,
            'action': 'new answer',
            'hash': filename,
            'ticket': ticket.id,
        }
    )
    try:
        if ticket.treatedBy.operator.role.modelsAuthorizations['ticket'].get('unassignedOnAnswer'):
            ticket.treatedBy = None
    except (AttributeError, KeyError, ObjectDoesNotExist, ValueError):
        pass

    if abuse_report.attachments:
        _save_attachments(
            filename,
            abuse_report.attachments,
            tickets=[ticket],
        )

    return _apply_business_rules(
        parsed_email=abuse_report,
        ticket=ticket,
        reply_recipient=recipient,
        reply_category=category,
        rules_type='EmailReply'
    )


def archive_if_timeout(report_id=None):
    """
        Archived report if not attached

        :param int report_id: The report id
    """
    report = Report.objects.get(id=report_id)

    if report.status != 'New':
        Logger.error(unicode(
            'Report %d not New, status : %s , Skipping ...' % (report_id, report.status)
        ))
        return

    report.ticket = None
    report.status = 'Archived'
    report.save()
    Logger.info(unicode('Report %d successfully archived' % (report_id)))


@transaction.atomic
def validate_with_defendant(report_id=None, user_id=None):
    """
        Reparse now validated `abuse.models.Report`

        :param int report_id: A Cerberus `abuse.models.Report` id
        :param int user_id: A Cerberus `abuse.models.User` id
    """
    report = Report.objects.get(id=report_id)
    user = User.objects.get(id=user_id)

    _reparse_validated(report, user)
    Logger.error(unicode('Report %d successfully processed' % (report_id)))


def _reparse_validated(report, user):

    ticket = None
    if all((report.defendant, report.category, report.service)):
        msg = 'Looking for opened ticket for (%s, %s, %s)'
        msg = msg % (report.defendant.customerId, report.category.name, report.service.name)
        Logger.debug(unicode(msg))
        ticket = database.search_ticket(report.defendant, report.category, report.service)

    # Checking specific processing workflow
    return _apply_business_rules(
        report=report,
        ticket=ticket,
        service=report.service,
        is_trusted=True,
        rules_type='Report'
    )


@transaction.atomic
def validate_without_defendant(report_id=None, user_id=None):
    """
        Archived invalid `abuse.models.Report`

        :param int report_id: A Cerberus `abuse.models.Report` id
        :param int user_id: A Cerberus `abuse.models.User` id
    """
    report = Report.objects.get(id=report_id)
    user = User.objects.get(id=user_id)

    report.ticket = common.create_ticket(report, attach_new=False)
    report.save()
    _send_emails_invalid_report(report)
    common.close_ticket(report.ticket, resolution_codename=settings.CODENAMES['invalid'], user=user)
    Logger.info(unicode('Ticket %d and report %d closed' % (report.ticket.id, report.id)))


def _send_emails_invalid_report(report):

    inject_proof = not bool(report.ticket.proof.count())

    common.send_email(
        report.ticket,
        [report.provider.email],
        settings.CODENAMES['not_managed_ip'],
        inject_proof=inject_proof
    )


@transaction.atomic
def cdn_request(report_id=None, user_id=None, domain_to_request=None):
    """
        Given `abuse.models.Report` contains CDN protected domain,
        try to resolve backend IP address

        :param int report_id: A Cerberus `abuse.models.Report` id
        :param int user_id: A Cerberus `abuse.models.User` id
        :param int domain_to_request: The domain to resolve
    """
    if not domain_to_request:
        raise Exception('No domain specified')

    report = Report.objects.get(id=report_id)
    user = User.objects.get(id=user_id)
    domain_to_request = domain_to_request.lower()

    ips = utils.get_ips_from_fqdn(domain_to_request)
    if not ips:
        raise Exception('Domain %s does not resolve' % domain_to_request)

    ReportItem.objects.create(
        itemType='FQDN',
        report=report,
        rawItem=domain_to_request
    )

    report.status = 'Attached'
    report.save()

    rules_applied = _apply_business_rules(
        report=report,
        domain_to_request=domain_to_request,
        rules_type='CDNRequest'
    )

    if not rules_applied:
        raise Exception('No workflow applied')
