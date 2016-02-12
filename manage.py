#!/usr/bin/env python
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
    Django manager
"""

import os
import sys
import unittest

sys.dont_write_bytecode = True

if __name__ == "__main__":

    if 'test' in sys.argv:
        unittest.TestLoader.sortTestMethodsUsing = lambda _, x, y: cmp(y, x)
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
    else:
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")

    import django
    django.setup()
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
