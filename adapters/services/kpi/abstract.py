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
    Defined KPI Service abstract Class
"""

import abc


class KPIServiceException(Exception):
    """ Exception that must be raised by KPIService implementations to ensure error are correctly handled.

        .. py:class:: KPIServiceException
    """
    def __init__(self, message):
        super(KPIServiceException, self).__init__(message)


class KPIServiceBase(object):
    """
        Abstract class defining a service to store event-based KPI. For example, an implementation might store those data
        in OVH PaaS TimeSeries,OpenTSDB, MongoDB, RDBMS or filesystem.

        The only exception allowed to be raised is ..py:exception:: KPIServiceException
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def new_ticket(self, ticket):
        """
            Log ticket creation

            :param object ticket: A Ticket Instance.
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'new_ticket'" % (cls))

    @abc.abstractmethod
    def new_ticket_assign(self, ticket):
        """
            Log ticket assignation

            :param object ticket: A Ticket Instance.
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'new_ticket_assign'" % (cls))

    @abc.abstractmethod
    def close_ticket(self, ticket):
        """
            Log ticket closing down

            :param object ticket: A Ticket Instance.
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'close_ticket'" % (cls))

    @abc.abstractmethod
    def new_report(self, report):
        """
            Log report creation

            :param object report: A Report Instance.
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'new_report'" % (cls))

    @abc.abstractmethod
    def new_api_request(self, endpoint, status_code, response_time):
        """
            Log api request

            :param str endpoint: The called API endpoint.
            :param int status_code: The HTTP response code
            :param int response_time: The elapsed time
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'new_api_request'" % (cls))
