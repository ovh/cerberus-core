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
    Cerberus email templates manager
"""

import json
import operator
from urllib import unquote

from django.core.exceptions import FieldError
from django.db import IntegrityError
from django.db.models import ObjectDoesNotExist, ProtectedError, Q
from django.forms.models import model_to_dict
from werkzeug.exceptions import (BadRequest, Forbidden, NotFound,
                                 InternalServerError)

from ...models import MailTemplate, Ticket
from ...services.email import EmailService, EmailServiceException

LANGUAGES = [language[0] for language in MailTemplate.TEMPLATE_LANG]
RECIPIENTS_TYPE = [r[0] for r in MailTemplate.RECIPIENT_TYPE]


def get_templates(**kwargs):
    """ Main endpoint, get all templates
    """
    filters = {}

    if kwargs.get('filters'):
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex.message))
    try:
        where = generate_request_filter(filters)
    except (AttributeError, KeyError, IndexError, FieldError,
            SyntaxError, TypeError, ValueError) as ex:
        raise BadRequest(str(ex.message))

    try:
        templates = MailTemplate.filter(where).order_by('name')
    except (AttributeError, KeyError, IndexError, FieldError,
            SyntaxError, TypeError, ValueError) as ex:
        raise BadRequest(str(ex.message))

    return [model_to_dict(t) for t in templates]


def generate_request_filter(filters):
    """ Generates filters from filter query string
    """
    where = [Q()]
    if 'where' in filters and len(filters['where']):
        try:
            keys = set(k for k in filters['where'])
            if 'in' in keys:
                for i in filters['where']['in']:
                    for key, val in i.iteritems():
                        where.append(reduce(operator.or_, [Q(**{key: i}) for i in val]))
            where = reduce(operator.and_, where)
        except (AttributeError, KeyError, FieldError,
                SyntaxError, ValueError) as ex:
            raise BadRequest(str(ex.message))
    else:
        where = reduce(operator.and_, where)
    return where


def show(template_id):
    """ Get template
    """
    template = None
    try:
        template = MailTemplate.get(id=template_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Template not found')
    return model_to_dict(template)


def create(body):
    """ Create email templates
    """
    try:
        body['codename'] = body['name'].strip().lower().replace(' ', '_')
        template, _ = MailTemplate.get_or_create(**body)
    except (KeyError, FieldError, IntegrityError):
        raise BadRequest('Invalid fields in body')
    return model_to_dict(template)


def update(template_id, body):
    """ Update an email templates
    """
    try:
        template = MailTemplate.get(id=template_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Template not found')
    try:
        MailTemplate.filter(pk=template.pk).update(**body)
        template = MailTemplate.get(pk=template.pk)
    except (FieldError, IntegrityError):
        raise BadRequest('Invalid fields in body')
    return model_to_dict(template)


def destroy(template_id):
    """ Remove email templates
    """
    template = None
    try:
        template = MailTemplate.get(id=template_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Template not found')
    try:
        template.delete()
        return {'message': 'Email template successfully removed'}
    except ProtectedError:
        raise Forbidden('Mail template still referenced in reports/tickets')


def get_prefetch_template(ticket_id, template_id, lang=None, ack_report=None):
    """
        Prefetch template with ticket infos
    """
    try:
        ticket = Ticket.get(id=ticket_id)
        mail_template = MailTemplate.get(id=template_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket or email template not found')

    if not lang and mail_template.recipientType != 'Defendant':
        lang = 'EN'

    try:
        prefetched_email = EmailService.prefetch_email_from_template(
            ticket,
            mail_template.codename,
            lang=lang,
            acknowledged_report=ack_report,
        )
    except EmailServiceException as ex:
        raise InternalServerError(str(ex))

    mail_template = model_to_dict(mail_template)
    mail_template['to'] = prefetched_email.recipients
    mail_template['subject'] = prefetched_email.subject
    mail_template['body'] = prefetched_email.body
    return mail_template


def get_recipients_type():
    """ Get MailTemplate supported recipeints type
    """
    return RECIPIENTS_TYPE


def get_supported_languages():
    """ Get Application supported languages
    """
    return LANGUAGES
