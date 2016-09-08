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
    Workflow event for Cerberus
"""

import operator

from datetime import datetime, timedelta
from time import mktime, time

from django.conf import settings
from django.contrib.auth.models import User
from django.db.models import ObjectDoesNotExist, Q

import database

from abuse.models import Ticket
from worker import Logger

WAITING = 'WaitingAnswer'
PAUSED = 'Paused'
ALARM = 'Alarm'
STATUS_SEQUENCE = [WAITING, ALARM, WAITING]
CERBERUS_BOT_USER = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])


def follow_the_sun():
    """
        Set tickets to alarm when user is away
    """
    now = int(time())
    where = [~Q(status='Open'), ~Q(status='Reopened'), ~Q(status='Paused'), ~Q(status='Closed')]
    where = reduce(operator.and_, where)

    for user in User.objects.filter(~Q(username=CERBERUS_BOT_USER.username)):
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
