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
    Defined Search Service abstract Class
"""

import abc


class SearchServiceException(Exception):
    """ Exception that must be raised by SearchService implementations to ensure error are correctly handled.

        .. py:class:: SearchServiceException
    """
    def __init__(self, message):
        super(SearchServiceException, self).__init__(message)


class SearchServiceBase(object):
    """
        Interface defining a search service used to index documents. For example, an implementation might store those data
        in Apache SolR, MongoDB, or RDBMS.

        The only exception allowed to be raised is ..py:exception:: SearchServiceException
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def index_email(self, parsed_email, filename, reports_id):
        """
            Index data in search service and map content with Cerberus report(s)

            :param ParsedEmail parsed_email: `ParsedEmail` instance
            :param str filename: The filename associated with the email
            :param list reports_id: The list of corresponding Cerberus report(s) id
            :raises SearchServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'index_email'" % (cls))

    @abc.abstractmethod
    def search_reports(self, query):
        """
            Search the matching content in the search service and eventually returns corresponding report(s) id.

            :param str query: The query
            :rtype: list
            :return: The list of matching report(s) id
            :raises SearchServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'search_reports'" % (cls))
