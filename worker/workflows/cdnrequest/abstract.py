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
    Defined CDNRequestWorkflowBase abstract class
"""

import abc


class CDNRequestWorkflowBase(object):
    """
        Astract class defining CDN provider interaction
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def identify(self, report, domain_to_request):
        """
            identify if the `abuse.models.Report` and the domain_to_request match the CDN provider

            :param `abuse.models.Report` report: A Cerberus report instance
            :param str domain_to_request: the domain name to request
            :return: If the workflow match
            :rtype: bool
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'identify'" % (cls))

    @abc.abstractmethod
    def apply(self, report, domain_to_request):
        """
            Request backend IP for given domain to CDN`

            :param `abuse.models.Report` report: A Cerberus report instance
            :param str domain_to_request: the domain name to request
            :return: If the workflow is applied
            :rtype: bool
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'apply'" % (cls))
