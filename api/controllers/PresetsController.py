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
    Ticket Worfklow Preset Manager
"""

import json
from urllib import unquote

from django.core.exceptions import FieldError
from django.db import transaction
from django.db.models import ObjectDoesNotExist, Q
from django.forms.models import model_to_dict
from werkzeug.exceptions import BadRequest, NotFound

from abuse.models import (MailTemplate, Ticket, TicketAction,
                          TicketActionParams, TicketWorkflowPreset,
                          TicketWorkflowPresetConfig, Role)
from api.controllers import TemplatesController

LANGUAGES = [language[0] for language in MailTemplate.TEMPLATE_LANG]
PRESET_FIELDS = [fld.name for fld in TicketWorkflowPreset._meta.fields]


def index(user, **kwargs):
    """
        Get all presets
    """
    # Parse filters from request
    filters = {}
    if kwargs.get('filters'):
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex.message))

    with_template = False
    if not filters.get('queryFields') or 'templates' in filters['queryFields']:
        with_template = True

    try:
        fields = filters['queryFields']
        if 'templates' in fields:
            fields.remove('templates')
    except KeyError:
        fields = PRESET_FIELDS

    try:
        presets = _get_ordered_presets(user, fields, with_template)
    except (KeyError, FieldError, ValueError) as ex:
        raise BadRequest(str(ex.message))

    return presets


def _get_ordered_presets(user, fields, with_template):

    presets = []
    preset_groups = TicketWorkflowPreset.objects.filter(
        roles=user.operator.role
    ).values_list(
        'groupId',
        flat=True
    ).distinct()

    for group in preset_groups:
        result = list(TicketWorkflowPreset.objects.filter(
            roles=user.operator.role,
            groupId=group
        ).values(
            *fields
        ).order_by(
            'orderId',
            'name'
        ))
        if with_template:
            for res in result:
                res['templates'] = list(TicketWorkflowPreset.objects.get(
                    id=res['id'],
                    roles=user.operator.role,
                ).templates.all().values_list(
                    'id',
                    flat=True
                ).distinct())
        presets.append({
            'groupId': group,
            'presets': result,
        })

    return presets


def get_prefetch_preset(user, ticket_id, preset_id, lang=None):
    """
        Prefetch preset with ticket infos
    """
    action = params = None
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        preset = TicketWorkflowPreset.objects.get(id=preset_id, roles=user.operator.role)
        if preset.config:
            action = model_to_dict(preset.config.action)
            if preset.config.params:
                params = {param.codename: param.value for param in preset.config.params.all()}
        preset = model_to_dict(preset)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket or preset not found')

    preset['templates'] = []
    templates_codename = MailTemplate.objects.filter(
        ticketworkflowpreset=preset['id']
    ).values_list(
        'codename',
        flat=True
    )
    templates_codename = list(set(templates_codename))

    for codename in templates_codename:
        template = MailTemplate.objects.get(codename=codename)
        resp = TemplatesController.get_prefetch_template(ticket.id, template.id, lang=lang)
        preset['templates'].append(resp)

    preset['action'] = action
    if action and params:
        preset['action']['params'] = params

    return preset


def show(user, preset_id):
    """
        Get given preset
    """
    try:
        preset = TicketWorkflowPreset.objects.get(id=preset_id, roles=user.operator.role)
    except (IndexError, ObjectDoesNotExist, ValueError, TypeError):
        raise NotFound('Preset not found')

    action = params = None
    if preset.config:
        action = model_to_dict(preset.config.action)
        if preset.config.params:
            params = {param.codename: param.value for param in preset.config.params.all()}

    preset = model_to_dict(preset)
    preset['templates'] = MailTemplate.objects.filter(ticketworkflowpreset=preset['id'])
    preset['templates'] = [model_to_dict(m) for m in preset['templates']]
    preset['action'] = action
    if action and params:
        preset['action']['params'] = params

    preset['roles'] = list(TicketWorkflowPreset.objects.get(
        id=preset['id']
    ).roles.all().values_list(
        'codename',
        flat=True
    ).distinct())

    return preset


@transaction.atomic
def create(user, body):
    """
        Create a new preset
    """
    if not all(key in body for key in ('templates', 'action', 'name')):
        raise BadRequest('Missing params in body, expecting templates, action and name')

    try:
        body['codename'] = body['name'].strip().lower().replace(' ', '_')
        existing = TicketWorkflowPreset.objects.filter(
            codename=body['codename'],
            name=body['name']
        ).count()
        if existing:
            transaction.rollback()
            raise BadRequest('Preset with same codename/name exists')
        preset = TicketWorkflowPreset.objects.create(codename=body['codename'], name=body['name'])
    except (AttributeError, FieldError, ValueError) as ex:
        raise BadRequest(ex)

    if body.get('action'):
        try:
            preset.config = __get_preset_config(body)
        except (AttributeError, KeyError, ObjectDoesNotExist, TypeError, ValueError):
            raise BadRequest('Invalid or missing params in action')

    if body.get('templates'):
        for template_id in body['templates']:
            try:
                template = MailTemplate.objects.get(id=template_id)
                preset.templates.add(template)
            except (AttributeError, KeyError, ObjectDoesNotExist, ValueError):
                raise BadRequest('Invalid template id')

    if body.get('roles'):
        preset.roles.clear()
        for role_codename in body['roles']:
            try:
                role = Role.objects.get(codename=role_codename)
                preset.roles.add(role)
            except (AttributeError, KeyError, ObjectDoesNotExist, ValueError):
                raise BadRequest('Invalid role codename')

    preset.save()
    return {'message': 'Preset successfully updated'}


@transaction.atomic
def update(user, preset_id, body):
    """
        Update preset
    """
    if not all(key in body and body.get(key) for key in ('codename', 'name')):
        raise BadRequest('Missing params in body, expecting codename and name')

    try:
        preset = TicketWorkflowPreset.objects.get(id=preset_id, roles=user.operator.role)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Preset not found')

    if TicketWorkflowPreset.objects.filter(~Q(id=preset_id), name=body['name']).count():
        raise BadRequest('Preset with same name already exists')

    if body.get('action'):
        try:
            preset.config = __get_preset_config(body)
        except (AttributeError, KeyError, ObjectDoesNotExist, TypeError, ValueError):
            raise BadRequest('Invalid or missing params in action')

    if body.get('templates') is not None:
        preset.templates.clear()
        for template_id in body['templates']:
            try:
                template = MailTemplate.objects.get(id=template_id)
                preset.templates.add(template)
            except (AttributeError, KeyError, ObjectDoesNotExist, ValueError):
                raise BadRequest('Invalid template id')

    if body.get('roles') is not None:
        preset.roles.clear()
        for role_codename in body['roles']:
            try:
                role = Role.objects.get(codename=role_codename)
                preset.roles.add(role)
            except (AttributeError, KeyError, ObjectDoesNotExist, ValueError):
                raise BadRequest('Invalid role codename')

    preset.name = body['name']
    preset.save()
    resp = show(user, preset.id)
    return resp


def __get_preset_config(body):
    """
        Get preset config based on body
    """
    action = TicketAction.objects.get(codename=body['action'].get('codename'))
    config = TicketWorkflowPresetConfig.objects.create(action=action)

    if body['action'].get('params'):
        for key, value in body['action'].get('params').iteritems():
            param, _ = TicketActionParams.objects.get_or_create(codename=key, value=value)
            config.params.add(param)

    return config


def delete(user, preset_id):
    """
        Delete Preset
    """
    try:
        TicketWorkflowPreset.objects.get(id=preset_id, roles=user.operator.role)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Preset not found')

    TicketWorkflowPreset.objects.filter(id=preset_id).delete()
    return index(user)


def update_order(user, body):
    """
        Update groupId/orderId for preset display
    """
    group_id = 0
    try:
        for group in body:
            order_id = 0
            for preset_dict in group['presets']:
                preset = TicketWorkflowPreset.objects.get(id=preset_dict['id'])
                preset.orderId = order_id
                preset.groupId = group_id
                preset.save()
                order_id += 1
            group_id += 1
    except (AttributeError, KeyError, ObjectDoesNotExist, ValueError):
        raise BadRequest('Bad Request')
    return index(user)
