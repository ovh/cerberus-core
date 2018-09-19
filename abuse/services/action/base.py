# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017, OVH SAS
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
    Defines Action Service abstract Class
"""

import abc
import inspect

from collections import namedtuple

ActionResult = namedtuple("ActionResult", ["todo_id", "status", "comment"])


class ActionServiceException(Exception):
    """
        Exception that must be raised by ActionServiceBase implementations
        to ensure error are handled correctly.

        .. py:class:: ActionServiceException
    """

    def __init__(self, message):
        super(ActionServiceException, self).__init__(message)


class ActionServiceBase(object):
    """
        This interface defines an action (callback)
        on defendant's service (block/shutdown etc ..)
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def close_service(self, ticket, user=None):
        """
            Close `abuse.models.Ticket` related `abuse.models.Service`

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
            :param in user: The id of the Cerberus User
            :raises `cerberus.services.action.base.ActionServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def close_all_services(self, ticket, user=None):
        """
            Close all `abuse.models.Defendant` `abuse.models.Service`

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
                               where `abuse.models.Defendant` is attached
            :param in user: The id of the Cerberus User
            :raises `cerberus.services.action.base.ActionServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def close_defendant(self, ticket, user=None):
        """
            Close `abuse.models.Defendant`, breach of contract

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
                               where `abuse.models.Defendant` is attached
            :param in user: The id of the Cerberus User
            :raises `cerberus.services.action.base.ActionServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def apply_action_on_service(self, ticket, action, ip_addr=None, user=None):
        """
            Apply given action on service

            :param int ticket: The id of the Cerberus `abuse.models.Ticket`
            :param int action: The id of the `abuse.models.ServiceAction`
            :param str ip_addr: The IP address
            :param in user: The id of the Cerberus User
            :raises `cerberus.services.action.abstract.ActionServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def list_actions_for_ticket(self, ticket):
        """
            List all available `abuse.models.ServiceAction`
            for a Cerberus ticket

            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :rtype list:
            :return: The list of possible `abuse.models.ServiceAction`
                for given ticket
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )
