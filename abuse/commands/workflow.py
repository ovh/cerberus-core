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
    Update Cerberus tickets status
"""

from datetime import datetime
from time import time, mktime

import click

from flask.cli import with_appcontext
from django.db.models import ObjectDoesNotExist

from ..models import Ticket, History


@click.command("ticket-workflow", short_help="Runs Cerberus ticket workflow.")
@with_appcontext
def run_workflow():

    update_waiting()
    update_paused()


def update_waiting():
    """
        Update waiting answer tickets
    """
    now = int(time())
    for ticket in Ticket.filter(status="WaitingAnswer"):
        if ticket.snoozeStart and now > int(
            mktime(ticket.snoozeStart.timetuple()) + ticket.snoozeDuration
        ):
            click.echo("[workflow] set status 'Alarm' for ticket %d" % ticket.id)
            _check_auto_unassignation(ticket)
            ticket.set_status("Alarm")


def _check_auto_unassignation(ticket):

    history = (
        ticket.ticketHistory.filter(actionType="ChangeStatus")
        .order_by("-date")
        .values_list("ticketStatus", flat=True)[:3]
    )

    status_sequence = ["WaitingAnswer", "Alarm", "WaitingAnswer"]

    try:
        models_config = ticket.treatedBy.operator.role.modelsAuthorizations
        unassigned_on_multiple_alarm = models_config["ticket"][
            "unassignedOnMultipleAlarm"
        ]
        if (
            unassigned_on_multiple_alarm
            and len(history) == 3
            and all([status_sequence[i] == history[i] for i in xrange(3)])
        ):
            History.log_ticket_action(
                ticket=ticket,
                action="change_treatedby",
                previous_value=ticket.treatedBy,
            )
            ticket.treatedBy = None
            ticket.alarm = True
            ticket.save()
    except (AttributeError, KeyError, ObjectDoesNotExist, ValueError):
        pass


def update_paused():
    """
        Update paused tickets
    """
    now = int(time())
    for ticket in Ticket.filter(status="Paused"):
        if now > int(mktime(ticket.pauseStart.timetuple()) + ticket.pauseDuration):
            if (
                ticket.previousStatus == "WaitingAnswer"
                and ticket.snoozeDuration
                and ticket.snoozeStart
            ):
                ticket.snoozeDuration += (datetime.now() - ticket.pauseStart).seconds

            ticket.pauseStart = None
            ticket.pauseDuration = None
            ticket.save()
            ticket.set_status(ticket.previousStatus)
