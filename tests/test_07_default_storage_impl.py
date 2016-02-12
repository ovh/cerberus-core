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

import os

from django.conf import settings
from django.test import TestCase

from adapters.services.storage.abstract import StorageServiceException
from default.adapters.services.storage.impl import FilesystemStorageService

ROOT_STORAGE_DIR = settings.GENERAL_CONFIG['email_storage_dir']
WRITTEN_FILE = "foo/bar.file"
FILE_CONTENT = "Hello world !"


class GlobalTestCase(TestCase):
    """
        Global setUp for tests
    """
    def setUp(self):
        pass

    def tearDown(self):
        """
            Cleanup files & directories
        """
        complete_file_path = os.path.join(ROOT_STORAGE_DIR, WRITTEN_FILE)
        if os.path.exists(complete_file_path):
            os.remove(complete_file_path)


class TestDefaultStorageImpl(GlobalTestCase):
    """
        Unit tests for storage default implementation
    """
    def test_read_write_delete(self):
        """
            Standard read / write /delete sequence that should succeed
        """
        storage = FilesystemStorageService(ROOT_STORAGE_DIR)
        self.assertTrue(os.path.exists(ROOT_STORAGE_DIR))

        storage.write(WRITTEN_FILE, FILE_CONTENT)
        full_file_path = os.path.join(ROOT_STORAGE_DIR, WRITTEN_FILE)
        self.assertTrue(os.path.exists(full_file_path))

        buf = storage.read(WRITTEN_FILE)
        self.assertEquals(FILE_CONTENT, buf)

        storage.delete(WRITTEN_FILE)
        self.assertFalse(os.path.exists(full_file_path))

    def test_cannot_read(self):
        """ File does not exist => should raise a StorageServiceException """
        with self.assertRaises(StorageServiceException):
            storage = FilesystemStorageService(ROOT_STORAGE_DIR)
            storage.read(WRITTEN_FILE)

    def test_cannot_write(self):
        """ Cannot write in /bin (dont run this test as root please !) ==> StorageServiceException """
        with self.assertRaises(StorageServiceException):
            storage = FilesystemStorageService("/bin")
            storage.write("foo", "bar")

    def test_cannot_delete(self):
        """ Try to delete a file that does not exist => StorageServiceException """
        with self.assertRaises(StorageServiceException):
            storage = FilesystemStorageService(ROOT_STORAGE_DIR)
            storage.delete(WRITTEN_FILE)
