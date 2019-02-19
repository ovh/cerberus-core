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

import click

from flask.cli import with_appcontext
from redis import Redis
from rq import Connection, Queue, Worker
from django.db import close_old_connections


class CustomWorker(Worker):
    def main_work_horse(self, *args, **kwargs):
        raise NotImplementedError("Test worker does not implement this method")

    def execute_job(self, *args, **kwargs):
        """Execute job in same thread/process, do not fork()"""
        close_old_connections()
        return self.perform_job(*args, **kwargs)


@click.command("run-worker", short_help="Runs a Cerberus worker.")
@click.option("queues", "--queues")
@with_appcontext
def run_worker(queues):

    from flask import current_app

    config = current_app.config["REDIS"]

    _queues = queues.split(",")

    with Connection(Redis(config["host"], config["port"])):

        qs = map(Queue, _queues) or [Queue()]
        worker = CustomWorker(qs)
        worker.work()
