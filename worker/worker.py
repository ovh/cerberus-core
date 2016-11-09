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
    Worker for Cerberus
"""

import argparse
import inspect
import os
import sys

CURRENTDIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
PARENTDIR = os.path.dirname(CURRENTDIR)
sys.path.insert(0, PARENTDIR)

# Init settings

import django
from django.conf import ImproperlyConfigured

try:
    django.setup()
    from django.conf import settings
except ImproperlyConfigured:
    from django.conf import global_settings, settings
    from config import settings as custom_settings

    for attr in dir(custom_settings):
        if not callable(getattr(custom_settings, attr)) and not attr.startswith("__"):
            setattr(global_settings, attr, getattr(custom_settings, attr))

    settings.configure()
    django.setup()

from redis import StrictRedis
from rq import Connection, Queue, Worker

from utils.logger import get_logger

Logger = get_logger(os.path.basename('worker'))


def main():
    """
        Init workers
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--queues', nargs='+', type=unicode, dest='queues', required=True)
    args = parser.parse_args()

    with Connection(connection=StrictRedis(**settings.REDIS)):

        qs = map(Queue, args.queues) or [Queue()]
        worker = Worker(qs)
        worker.work()


if __name__ == "__main__":
    main()
