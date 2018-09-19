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


from copy import deepcopy

from django.db.models import ObjectDoesNotExist
from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from . import tickets as TicketsController
from ...models import AbusePermission, Resolution, Ticket
from ...tasks import enqueue


ACTIONS_PARAMS = {
    "waiting_answer_then_action": {
        "update_status": "waitinganswer",
        "task_params": {
            "task_name": "action.schedule_action",
            "force": True,
            "close_ticket": False,
            "bypass_status": True,
        },
        "task_extras": ["ip_addr", "seconds"],
    },
    "waiting_answer_then_action_and_close": {
        "update_status": "waitinganswer",
        "task_params": {
            "task_name": "action.schedule_action",
            "force": True,
            "close_ticket": True,
            "bypass_status": True,
        },
        "task_extras": ["ip_addr", "seconds", "resolution_id"],
    },
    "action_then_waiting_answer": {
        "task_params": {
            "task_name": "action.schedule_action",
            "force": True,
            "bypass_status": True,
            "seconds": 5,
            "status": "WaitingAnswer",
            "close_ticket": False,
        },
        "task_extras": ["ip_addr", "snooze_duration"],
    },
    "action_then_close": {
        "task_params": {
            "task_name": "action.schedule_action",
            "force": True,
            "bypass_status": True,
            "seconds": 5,
        },
        "task_extras": ["ip_addr", "resolution_id"],
    },
    "waiting_answer": {"update_status": "waitinganswer"},
    "close_with_resolution": {"update_status": "closed"},
    "pause_ticket": {"update_status": "paused"},
}


def interact(ticket_id, body, user):
    """
        Magic endpoint to save operator's time
    """
    if not _precheck_user_interact_authorizations(user, body):
        raise Forbidden("You are not allowed to use this interact parameters")
    try:
        ticket = Ticket.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Ticket not found")

    action = body["action"]

    try:
        _parse_interact_action(ticket, action, user)
    except (AttributeError, KeyError, ValueError, TypeError) as ex:
        raise BadRequest(str(ex))

    if body.get("emails"):
        for params in body["emails"]:
            enqueue(
                "email.send_ticket_email",
                ticket_id=ticket.id,
                subject=params["subject"],
                body=params["body"],
                category=params["category"],
                recipients=params["to"],
                attachments=params.get("attachments"),
                attach_email_thread=params.get("attachEmailThread"),
                user_id=user.id,
            )

    return {"message": "Ticket successfully updated"}


def _parse_interact_action(ticket, action, user):
    """ Parse action of interact endpoint's body
    """
    resp = {"message": "OK"}

    # Checking params
    resolution_id = None
    if action.get("params") and action["params"].get("resolution"):
        resolution_id = int(action["params"]["resolution"])
        if not Resolution.filter(id=resolution_id).exists():
            raise NotFound("Ticket resolution not found")

    if not resolution_id and action["codename"] in (
        "waiting_answer_then_action_and_close",
        "action_then_close",
        "close_with_resolution",
    ):
        raise BadRequest("Missing resolution")

    params = ACTIONS_PARAMS.get(action["codename"])
    if not params:
        raise NotFound("Action not found")

    action_id = ip_addr = None
    if "action" in action["codename"]:
        action_id = int(action["params"]["action"])
        ip_addr = action["params"].get("ip")
        if not _check_action_rights(ticket, action_id, user):
            raise Forbidden("Invalid permission for action")

    snooze_duration = seconds = 5
    if action["params"].get("snoozeDuration"):
        snooze_duration = seconds = int(action["params"]["snoozeDuration"])
        if seconds > 10000000:
            raise BadRequest("Invalid snooze duration")

    status_param = {
        "waitinganswer": {"snoozeDuration": seconds},
        "closed": {"resolution": resolution_id},
        "paused": {"pauseDuration": action["params"].get("pauseDuration")},
    }

    # Update ticket status
    if params.get("update_status"):
        status = params["update_status"]
        resp = TicketsController.update_status(
            ticket, status, status_param[status], user
        )

    # Enqueue async task
    if params.get("task_params"):
        task_params = deepcopy(params["task_params"])
        task_name = task_params.pop("task_name")
        task_params["user_id"] = user.id
        if params.get("task_extras"):
            for extra in params["task_extras"]:
                task_params[extra] = locals()[extra]
        enqueue(task_name, ticket=ticket.id, action=action_id, **task_params)

    return resp


def _precheck_user_interact_authorizations(user, body):
    """
       Check if user's interact parameters are allowed
    """
    authorizations = user.operator.role.modelsAuthorizations
    if authorizations.get("ticket") and authorizations["ticket"].get("interact"):
        return body["action"]["codename"] in authorizations["ticket"]["interact"]
    return False


def _check_action_rights(ticket, action_id, user):
    """
        Check if user can set action
    """
    try:
        perm = AbusePermission.get(user=user, category=ticket.category)
        authorized = perm.profile.actions.filter(id=action_id).exists()
        if not authorized:
            return False
    except ObjectDoesNotExist:
        return False
    return True
