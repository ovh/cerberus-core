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
    Stats event producer for Cerberus
"""

import inspect
import os
import sys

CURRENTDIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
PARENTDIR = os.path.dirname(CURRENTDIR)
sys.path.insert(0, PARENTDIR)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
django.setup()

import logutils

from django.conf import settings
from redis import Redis
from rq import Queue

from utils.logger import get_logger


Logger = get_logger('stat')
Worker = Queue(connection=Redis(**settings.REDIS))


def main():
    """
        Create worker event for stats
    """
    Logger.debug(unicode('Starting update_defendants_history'))
    Worker.enqueue('stats.update_defendants_history', timeout=43200)

    for handler in Logger.handlers:
        if isinstance(handler, logutils.queue.QueueHandler):
            handler.queue.join()

if __name__ == "__main__":
    main()
