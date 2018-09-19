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

from .base import ActionResult, ActionServiceBase, ActionServiceException
from ...models import ServiceAction, Ticket


class DefaultActionService(ActionServiceBase):
    """
        Default implementation of ActionServiceBase
    """

    def __init__(self, config, logger=None):
        pass

    def close_service(self, ticket, user=None):
        """
            Close `abuse.models.Ticket` related `abuse.models.Service`

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
            :param in user: The id of the Cerberus User
            :raises `cerberus.services.action.base.ActionServiceException`
        """
        pass

    def close_all_services(self, ticket, user=None):
        """
            Close all `abuse.models.Defendant` `abuse.models.Service`

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
                               where `abuse.models.Defendant` is attached
            :param in user: The id of the Cerberus User
            :raises `cerberus.services.action.base.ActionServiceException`
        """
        pass

    def close_defendant(self, ticket, user=None):
        """
            Close `abuse.models.Defendant`, breach of contract

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
                               where `abuse.models.Defendant` is attached
            :param in user: The id of the Cerberus User
            :raises `cerberus.services.action.base.ActionServiceException`
        """
        pass

    def apply_action_on_service(self, ticket, action, ip_addr=None, user=None):
        """
            Apply given action on service

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
            :param int action: The id of the `abuse.models.ServiceAction`
            :param str ip_addr: The IP address
            :param int user: The id of the Cerberus `User`
            :raises `cerberus.services.action.base.ActionServiceException`
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise ActionServiceException(
                    "Ticket {} can not be found in DB".format(ticket)
                )

        if not isinstance(action, ServiceAction):
            try:
                action = ServiceAction.get(id=action)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise ActionServiceException(
                    "Action {} can not be found in DB".format(action)
                )

        return ActionResult(todo_id="123456", status="ok", comment="ok")

    def list_actions_for_ticket(self, ticket):
        """
            List all available `abuse.models.ServiceAction`
            for a Cerberus ticket

            :param `abuse.models.Ticket` ticket: A ticket instance
            :rtype list:
            :return: list possible `abuse.models.ServiceAction` for ticket
        """
        if not isinstance(ticket, Ticket):
            try:
                ticket = Ticket.get(id=ticket)
            except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
                raise ActionServiceException(
                    "Ticket {} can not be found in DB".format(ticket)
                )

        return ServiceAction.all()
