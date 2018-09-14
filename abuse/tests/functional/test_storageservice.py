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
    Unit tests for storage default implementation
"""

from ...services.storage import StorageService
from ...services.storage.base import StorageServiceException

from ...tests.setup import CerberusTest

WRITTEN_FILE = "test"
FILE_CONTENT = "Hello world !"


class TestDefaultStorageImpl(CerberusTest):
    """
        Unit tests for storage default implementation
    """
    def test_read_write_delete(self):
        """
            Standard read / write /delete sequence that should succeed
        """
        storage = StorageService()
        storage.write(WRITTEN_FILE, FILE_CONTENT)

        buf = storage.read(WRITTEN_FILE)
        self.assertEquals(FILE_CONTENT, buf)
        storage.delete(WRITTEN_FILE)

    def test_cannot_read(self):
        """ File does not exist => should raise a StorageServiceException """
        with self.assertRaises(StorageServiceException):
            storage = StorageService()
            storage.read(WRITTEN_FILE)

    def test_cannot_delete(self):
        """ Try to delete a file that does not exist => StorageServiceException """
        with self.assertRaises(StorageServiceException):
            storage = StorageService()
            storage.delete(WRITTEN_FILE)
