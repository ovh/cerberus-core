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
    Defined Action Service abstract Class
"""

import abc
from collections import namedtuple

ActionResult = namedtuple('ActionResult', ['todo_id', 'status', 'comment'])


class ActionServiceException(Exception):
    """
        Exception that must be raised by ActionService implementations
        to ensure error are correctly handled.

        .. py:class:: ActionServiceException
    """
    def __init__(self, message):
        super(ActionServiceException, self).__init__(message)


class ActionServiceBase(object):
    """
        Interface defining a action (callback) on defendant service (block/shutdown etc ..)

        The only exception allowed to be raised is ..py:exception:: ActionServiceException
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def close_service(self, ticket, user=None):
        """
            Close `abuse.models.Ticket` related `abuse.models.Service`

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
            :param in user: The id of the Cerberus User
            :raises `adapters.services.action.abstract.ActionServiceException`: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError(
            "'%s' object does not implement the method 'close_service'" % (cls)
        )

    @abc.abstractmethod
    def close_all_services(self, ticket, user=None):
        """
            Close all `abuse.models.Defendant` `abuse.models.Service`

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
                               where `abuse.models.Defendant` is attached
            :param in user: The id of the Cerberus User
            :raises `adapters.services.action.abstract.ActionServiceException`: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError(
            "'%s' object does not implement the method 'close_all_services'" % (cls)
        )

    @abc.abstractmethod
    def close_defendant(self, ticket, user=None):
        """
            Close `abuse.models.Defendant`, breach of contract

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
                               where `abuse.models.Defendant` is attached
            :param in user: The id of the Cerberus User
            :raises `adapters.services.action.abstract.ActionServiceException`: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError(
            "'%s' object does not implement the method 'close_defendant'" % (cls)
        )

    @abc.abstractmethod
    def apply_action_on_service(self, ticket, action, ip_addr=None, user=None):
        """
            Apply given action on service

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
            :param int action: The id of the Cerberus `abuse.models.ServiceAction`
            :param str ip_addr: The IP address
            :param in user: The id of the Cerberus User
            :raises `adapters.services.action.abstract.ActionServiceException`: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError(
            "'%s' object does not implement the method 'apply_action_on_service'" % (cls)
        )

    @abc.abstractmethod
    def get_action_for_timeout(self, ticket):
        """
            Returns action to apply when ticket timeout

            :param `abuse.models.Ticket` ticket: A Cerberus `abuse.models.Ticket` instance
            :rtype: `abuse.models.ServiceAction`
            :return: The `abuse.models.ServiceAction` to apply
            :raises `adapters.services.action.abstract.ActionServiceException`: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError(
            "'%s' object does not implement the method 'get_action_for_timeout'" % (cls)
        )

    @abc.abstractmethod
    def list_actions_for_ticket(self, ticket):
        """
            List all available `abuse.models.ServiceAction` for a Cerberus ticket

            :param `abuse.models.Ticket` ticket: A Cerberus `abuse.models.Ticket` instance
            :rtype list:
            :return: The list of possible `abuse.models.ServiceAction` for given ticket
        """
        cls = self.__class__.__name__
        raise NotImplementedError(
            "'%s' object does not implement the method 'list_actions_for_ticket'" % (cls)
        )
