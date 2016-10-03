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
    Defined TicketAnswerWorkflow abstract class
"""

import abc


class TicketAnswerWorkflowBase(object):
    """
        Abstract class defining workflow in ticket answer processing
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def identify(self, ticket, abuse_report, recipient, category):
        """
            identify if the `abuse.models.Report` match this workflow.

            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `worker.parsing.parsed.ParsedEmail` abuse_report: the email
            :param str recipient: The recipient of the answer
            :param str category: defendant, plaintiff or other
            :return: If the workflow match
            :rtype: bool
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'identify'" % (cls))

    @abc.abstractmethod
    def apply(self, ticket, abuse_report, recipient, category):
        """
            Apply specific answer workflow on given `abuse.models.Ticket`

            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `worker.parsing.parsed.ParsedEmail` abuse_report: the email
            :param str recipient: The recipient of the answer
            :param str category: defendant, plaintiff or other
            :return: If the workflow is applied
            :rtype: bool
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'apply'" % (cls))
