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
    Logger for Cerberus
"""

import logging
import Queue
import sys

from django.conf import settings
from djehouty.libgelf.handlers import GELFTCPSocketHandler
from logutils.queue import QueueHandler, QueueListener

HANDLERS = settings.LOG['handlers']


def get_logger(name=__name__):
    """
        Get logger with handlers
    """
    name = name.replace('.py', '')
    queue = Queue.Queue(-1)
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    handlers = []
    for handler in HANDLERS:
        if handler == 'gelf':
            handlers.append(get_gelf_handler(name=name))
        elif handler == 'stderr':
            handlers.append(get_stderr_handler())

    listener = QueueListener(queue, *handlers)
    listener.start()
    queue_handler = QueueHandler(queue)
    logger.addHandler(queue_handler)
    return logger


def get_stderr_handler():
    """
        Get stderr handler
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    return handler


def get_gelf_handler(name=None):
    """
        Get gelf logger
    """
    static_fields = settings.LOG['gelf']['static_fields']
    static_fields['app'] = name

    gelf_handler = GELFTCPSocketHandler(
        host=settings.LOG['gelf']['host'],
        port=settings.LOG['gelf']['port'],
        static_fields=static_fields,
        use_tls=True,
        level=logging.DEBUG,
        null_character=True,
    )
    return gelf_handler
