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
    Default Implementation of Action Service

"""
from django.db.models import ObjectDoesNotExist

from abuse.models import ServiceAction, Ticket
from adapters.services.action.abstract import (ActionResult, ActionServiceBase,
                                               ActionServiceException)


class DefaultActionService(ActionServiceBase):
    """
        Default implementation of ActionServiceBase
    """

    @staticmethod
    def apply_action_on_service(ticket, action, ip_addr=None, user=None):
        """
            Apply given action on service

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
            :param int action: The id of the Cerberus `abuse.models.ServiceAction`
            :param str ip_addr: The IP address
            :param int user: The id of the Cerberus `User`
            :raises `adapters.services.action.abstract.ActionServiceException`: if any error occur
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.objects.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise ActionServiceException('Ticket %s cannot be found in DB. Skipping...' % (str(ticket)))

        if not isinstance(action, ServiceAction):
            try:
                action = ServiceAction.objects.get(id=action)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise ActionServiceException('Action %s cannot be found in DB. Skipping...' % (str(action)))

        return ActionResult(todo_id='123456', status='ok', comment='ok')

    @staticmethod
    def get_action_for_timeout(ticket):
        """
            Returns action to apply when ticket timeout

            :param `abuse.models.Ticket` ticket: A Cerberus Ticket instance
            :rtype: `abuse.models.ServiceAction`
            :returns: The `abuse.models.ServiceAction` to apply
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.objects.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise ActionServiceException('Ticket %s cannot be found in DB. Skipping...' % (str(ticket)))

        action = None
        if ServiceAction.objects.count():
            action = ServiceAction.objects.all()[:1][0]

        return action

    @staticmethod
    def list_actions_for_ticket(ticket):
        """
            List all available `abuse.models.ServiceAction` for a Cerberus ticket

            :param `abuse.models.Ticket` ticket: A Cerberus `abuse.models.Ticket` instance
            :rtype list:
            :returns: The list of possible `abuse.models.ServiceAction` for given ticket
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.objects.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise ActionServiceException('Ticket %s cannot be found in DB. Skipping...' % (str(ticket)))

        actions = ServiceAction.objects.all()
        return actions
