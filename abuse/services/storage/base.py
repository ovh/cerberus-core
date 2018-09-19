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
    Define Storage Service abstract Class
"""

import abc
import inspect


class StorageServiceException(Exception):
    """ Exception that must be raised by StorageService implementations.

        .. py:class:: StorageServiceException
    """

    def __init__(self, message):
        super(StorageServiceException, self).__init__(message)


class StorageServiceBase(object):
    """
        Interface defining a storage service used to store documents.
        For example, an implementation might store those data
        in OpenStack Swift, MongoDB, RDBMS or filesystem.

        ..py:exception:: StorageServiceException
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def read(self, object_name):
        """
            Read an existing object.

            :param str object_name: Unique object name to be read
            :rtype: raw
            :return:  Content of the object
            :raises `cerberus.services.storage.base.StorageServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def write(self, object_name, data):
        """
            Write a new object.

            :param str object_name: Unique object name to be pushed
            :param raw data: Associated data (might be binary content)
            :rtype: bool
            :return: `True` if everything went ok, `False` otherwise
            :raises `cerberus.services.storage.base.StorageServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def delete(self, object_name):
        """
            Triggered when an object must be removed.

            :param str object_name: Unique object name that must be removed
            :raises `cerberus.services.storage.base.StorageServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )
