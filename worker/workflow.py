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
from django.db.models import Q

import database

from abuse.models import Ticket
from worker import Logger

WAITING = 'WaitingAnswer'
PAUSED = 'Paused'
ALARM = 'Alarm'
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
                ticket.status = ALARM
                ticket.snoozeStart = None
                ticket.snoozeDuration = None
                ticket.previousStatus = WAITING
                ticket.reportTicket.all().update(status='Attached')
                ticket.save()
                database.log_action_on_ticket(ticket, 'change status from %s to %s' % (ticket.previousStatus, ticket.status))

        except (AttributeError, ValueError) as ex:
            Logger.debug(unicode('Error while updating ticket %d : %s' % (ticket.id, ex)))


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
                database.log_action_on_ticket(ticket, 'change status from %s to %s' % (ticket.previousStatus, ticket.status))
                ticket.save()

        except (AttributeError, ValueError) as ex:
            Logger.debug(unicode('Error while updating ticket %d : %s' % (ticket.id, ex)))
