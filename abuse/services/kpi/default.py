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


from .base import KPIServiceBase


class DefaultKPIService(KPIServiceBase):
    """
        Default dummy implementation
    """
    def __init__(self, config, logger=None):
        pass

    def new_ticket(self, ticket):
        """
            Log ticket creation

            :param object ticket: A Ticket Instance.
        """
        pass

    def new_ticket_assign(self, ticket):
        """
            Log ticket assignation

            :param object ticket: A Ticket Instance.
        """
        pass

    def close_ticket(self, ticket):
        """
            Log ticket closing down

            :param object ticket: A Ticket Instance.
        """
        pass

    def new_report(self, report):
        """
            Log report creation

            :param object report: A Report Instance.
        """
        pass
