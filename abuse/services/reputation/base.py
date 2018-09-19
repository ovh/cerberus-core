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
    Defines Reputation Service abstract Class
"""

import abc
import inspect


class ReputationServiceException(Exception):
    """ Exception that must be raised by ReputationService implementations
    to ensure error are correctly handled.

        .. py:class:: ReputationServiceException
    """

    def __init__(self, message):
        super(ReputationServiceException, self).__init__(message)


class ReputationServiceBase(object):
    """
        Abstract class defining Reputation Service,
        usefull to know if IP address/URL are blacklisted.

        ..py:exception:: ReputationServiceException
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_ip_rbl_reputations(self, ip_addr):
        """
            Return RBL reputations for given IP

            Return a list of dict : i.e

            [
                {
                    'shortName': 'SH',
                    'fullName': 'Spamhaus',
                    'result': '127.0.0.1'
                }
            ]

            :param str ip_addr: The IP address.
            :return: Check against different RBL providers
            :rtype: list
            :raises `cerberus.services.reputation.base.ReputationServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def get_ip_external_reputations(self, ip_addr):
        """
            Return external reputations for given IP

            Return a list of dict : i.e

            [
                {
                    'shortName': 'SC',
                    'fullName': 'SpamCop,
                    'result': '456'
                }
            ]

            :param str ip_addr: The IP address.
            :return: Check against different external providers
            :rtype: list
            :raises `cerberus.services.reputation.base.ReputationServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def get_ip_external_details(self, ip_addr, short_name):
        """
            Return external reputation for given IP and given provider

            Return a list of dict : i.e

            [
                {
                    'detail': '...........',
                    'timestamp': 123456789,
                    'result': '124'
                },
                {
                    'detail': '...........',
                    'timestamp': 123456799,
                    'result': '332'
                }
            ]

            :param str ip_addr: The IP address.
            :param str short_name: The short_name of the provider
            :return: Details for provider
            :rtype: list
            :raises `cerberus.services.reputation.base.ReputationServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def get_url_external_reputations(self, url):
        """
            Return external reputations for given url

            Return a list of dict : i.e

            [
                {
                    'shortName': 'GSB',
                    'fullName': 'GoogleSafeBrowsing',
                    'result': True
                }
            ]

            :param str url: The URL.
            :return: Check against different external providers
            :rtype: list
            :raises `cerberus.services.reputation.base.ReputationServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def get_ip_internal_reputations(self, ip_addr):
        """
            Use your internal tool/DB to check reputation for given IP

            Return a list of dict : i.e

            [
                {
                    'shortName': 'MN',
                    'fullName': 'Monitoring',
                    'result': '123',
                    'blacklisted': False,
                    'lastEvent': None,
                }
            ]

            :param str ip_addr: The IP address.
            :return: Check against different internal providers
            :rtype: list
            :raises `cerberus.services.reputation.base.ReputationServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def get_ip_tools(self, ip_addr):
        """
            Generates link to online reputation tools

            Return a list of dict : i.e

            [
                {
                    'shortName': 'TT',
                    'fullName': 'Test',
                    'uri': 'https://bla.com/ip=1.2.3.4',
                }
            ]
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )
