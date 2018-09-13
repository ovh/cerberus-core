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
    Define TicketSchedulingAlgorithm abstract class
"""

import abc


class TicketSchedulingAlgorithmBase(object):
    """
        Abstract class defining `abuse.models.Ticket`
        scheduling algorithm base
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def count(self, **kwargs):
        """
            Returns how many `abuse.models.Ticket` are available
            according to scheduling algorithm

            :return: The number of tickets available
            :rtype: int
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'count'" % (cls))

    @abc.abstractmethod
    def get_tickets(self, user=None, **kwargs):
        """
            Returns available `abuse.models.Ticket` according
            to scheduling algorithm

            :return: (the list of `abuse.models.Ticket`
                     dict (model_to_dict) , number of tickets)
            :rtype: tuple
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'get_tickets'" % (cls))
