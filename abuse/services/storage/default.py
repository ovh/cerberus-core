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
    Default Storage Service impl
"""

import os

from .base import StorageServiceBase, StorageServiceException


class FilesystemStorageService(StorageServiceBase):
    """
        Implementation of the StorageServiceBase
        to provide a storage service using the host filesystem.
    """

    def __init__(self, config, logger=None):
        """
            Constructor

            :param str context: Root directory where files are stored
            :raises `cerberus.services.storage.base.StorageServiceException`
        """
        context = config["directory"]
        self._root_dir = context

        # Check path exists else create it
        try:
            if context and not os.path.exists(context):
                os.makedirs(context)
        except Exception as ex:
            raise StorageServiceException(ex)

    def read(self, filename):
        """
            Read an existing file.

            :param str filename: file to read
            :rtype: raw
            :return:  Content of the file
            :raises `cerberus.services.storage.base.StorageServiceException`
        """
        target = os.path.join(self._root_dir, filename)

        if not os.path.exists(target):
            raise StorageServiceException("File does not exist.")

        try:
            with open(target, "r") as fd:
                return fd.read()
        except Exception as ex:
            raise StorageServiceException(ex)

    def write(self, filename, data):
        """
            Write a brand new file.

            :param str filename: Filename of the file to be written
            :param raw data: Associated data (might be binary content)
            :rtype: bool
            :return: `True` if everything went ok, `False` otherwise
            :raises `cerberus.services.storage.base.StorageServiceException`
        """
        try:
            target = os.path.join(self._root_dir, filename)

            # Check whether submitted path exists else, create it.
            dirname = os.path.dirname(target)
            if dirname and not os.path.exists(dirname):
                os.makedirs(dirname)

            with open(target, "wb") as fd:
                fd.write(data)

            return True
        except Exception as ex:
            raise StorageServiceException(ex)

    def delete(self, filename):
        """
            Remove an existing file.

            :param str filename: Name of the file to remove
            :raises `cerberus.services.storage.base.StorageServiceException`
        """
        try:
            target = os.path.join(self._root_dir, filename)

            if not os.path.exists(target):
                raise StorageServiceException("File not found.")

            os.remove(target)
        except Exception as ex:
            raise StorageServiceException(ex)
