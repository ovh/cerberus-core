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
    Update statistic of Ticket/Report by defendant
"""

from datetime import datetime

from django.db.models import Q

from abuse.models import Category, Defendant, Report, Stat, Ticket
from worker import Logger


def update_defendants_history():
    """
        Update defendant stats (tickets and report)
    """
    defendants = Defendant.objects.all().values('id', 'customerId')
    categories = Category.objects.all().values_list('name', flat=True)
    now = datetime.now()

    for defendant in defendants:
        __update_history(defendant, categories, now)


def __update_history(defendant, categories, now):
    """
        Update history for given defendant
    """
    Logger.debug(str('Updating history for defendant %s' % (defendant['customerId'])))
    for category in categories:

        reports = Report.objects.filter(~Q(status='Archived'), category=category, defendant_id=defendant['id']).count()
        tickets = Ticket.objects.filter(~Q(status='Closed'), category=category, defendant_id=defendant['id']).count()
        stats = __get_last_stats(defendant['id'], category)

        if not len(stats) or reports != stats[0].reports or tickets != stats[0].tickets:

            Stat.objects.create(
                defendant_id=defendant['id'],
                category_id=category,
                tickets=tickets,
                reports=reports,
                date=now,
            )


def __get_last_stats(defendant_id, category):
    """
        Get last stats
    """
    stats = Stat.objects.filter(
        defendant_id=defendant_id,
        category=category,
    ).order_by('-date')[:1]
    return stats
