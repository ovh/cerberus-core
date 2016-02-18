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
    Ticket functions for worker
"""

from datetime import timedelta

from django.db.models import ObjectDoesNotExist

from abuse.models import Ticket
from utils import utils
from worker import Logger


def delay_jobs(ticket=None, delay=None, back=True):
    """
        Delay pending jobs for given `abuse.models.Ticket`

        :param `abuse.models.Ticket` ticket: The Cerberus ticket
        :param int delay: Postpone duration
        :param bool back: In case of unpause, reschedule jobs with effectively elapsed time
    """
    if not delay:
        Logger.error(unicode('Missing delay. Skipping...'))
        return

    if not isinstance(ticket, Ticket):
        try:
            ticket = Ticket.objects.get(id=ticket)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            Logger.error(unicode('Ticket %d cannot be found in DB. Skipping...' % (ticket)))
            return

    list_of_job_instances = utils.scheduler.get_jobs(
        until=timedelta(days=5),
        with_times=True
    )

    for job in ticket.jobs.all():
        if job.asynchronousJobId in utils.scheduler:
            for scheduled_job in list_of_job_instances:
                if scheduled_job[0].id == job.asynchronousJobId:
                    if back:
                        date = scheduled_job[1] - delay
                    else:
                        date = scheduled_job[1] + delay
                    utils.scheduler.change_execution_time(
                        scheduled_job[0],
                        date
                    )
                    break
