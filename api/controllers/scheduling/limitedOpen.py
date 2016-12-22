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
    Defined GlobalSchedulingAlgorithm (standard) class
"""

import operator

from collections import Counter
from datetime import datetime, timedelta

from django.db.models import Count, Q

from abuse.models import Ticket
from api.controllers.scheduling import common
from api.controllers.scheduling.abstract import TicketSchedulingAlgorithmBase

TODO_TICKET_STATUS_FILTERS = (['Open'],)
TODO_TICKET_PRIORITY_FILTERS = ('Normal', 'Low')
TICKET_FIELDS = [fld.name for fld in Ticket._meta.fields]


class LimitedOpenSchedulingAlgorithm(TicketSchedulingAlgorithmBase):
    """
        Class defining standard `abuse.models.Ticket` scheduling algorithm
    """
    def count(self, **kwargs):

        if kwargs.get('where'):
            where = kwargs['where']
            rejected = get_defendant_to_reject(where=where)
            count = Ticket.objects.filter(
                ~Q(defendant__in=rejected),
                where,
                escalated=False,
                status='Open',
                priority__in=TODO_TICKET_PRIORITY_FILTERS
            ).order_by('id').distinct().count()
        else:
            rejected = get_defendant_to_reject()
            where = [~Q(defendant__in=rejected)]
            where = reduce(operator.and_, where)
            count = Ticket.objects.filter(
                where,
                escalated=False,
                status='Open',
                priority__in=TODO_TICKET_PRIORITY_FILTERS
            ).order_by('id').distinct().count()

        return count

    def get_tickets(self, user=None, **kwargs):
        """
            Returns available `abuse.models.Ticket` according to scheduling algorithm

            Tickets selections:

            By priority of ticket status  (see TODO_TICKET_STATUS_FILTERS)
                By priority of ticket priorities (see TODO_TICKET_PRIORITY_FILTERS)
                    By user, others then treatedBy nobody
        """
        filters = {}
        if kwargs.get('filters'):
            filters = kwargs['filters']

        try:
            limit = int(filters['paginate']['resultsPerPage'])
            offset = int(filters['paginate']['currentPage'])
        except KeyError:
            limit = 10
            offset = 1

        where = common.get_user_filters(user)
        where.extend(common.get_generic_filters(filters))
        where.append(Q(escalated=False))
        order_by = ['modificationDate', '-reportTicket__tags__level']

        if filters.get('onlyUnassigned'):
            where.append(Q(treatedBy=None))
            treated_by_filters = [{'treatedBy': None}]
        else:
            treated_by_filters = common.get_treated_by_filters(user)

        temp_where = reduce(operator.and_, where)
        rejected = get_defendant_to_reject(where=temp_where)
        where.append(~Q(defendant__in=rejected))
        where = list(set(where))
        where = reduce(operator.and_, where)

        nb_record = Ticket.objects.filter(
            where,
            status='Open',
            priority__in=TODO_TICKET_PRIORITY_FILTERS,
        ).distinct().count()

        res = []
        ids = set()

        for ticket_status in TODO_TICKET_STATUS_FILTERS:
            for priority in TODO_TICKET_PRIORITY_FILTERS:
                for filters in treated_by_filters:
                    tickets = get_specific_filtered_todo_tickets(where, ids, priority,
                                                                 ticket_status, filters,
                                                                 order_by, limit, offset)
                    ids.update([t['id'] for t in tickets])
                    res.extend(tickets)
                    if len(res) > limit * offset:
                        return res[(offset - 1) * limit:limit * offset], nb_record

        return res[(offset - 1) * limit:limit * offset], nb_record


def get_specific_filtered_todo_tickets(where, ids, priority, status,
                                       treated_by, order_by, limit, offset):
    """
        Returns a list of `abuse.models.Ticket` dict-mapping based on multiple filters
    """
    res = []

    while True:
        tickets = Ticket.objects.filter(
            where,
            ~Q(id__in=ids),
            priority=priority,
            status__in=status,
            **treated_by
        ).values(
            *TICKET_FIELDS
        ).order_by(
            *order_by
        ).annotate(
            attachedReportsCount=Count('reportTicket')
        ).distinct()[:limit * offset]

        ids.update([t['id'] for t in tickets])

        for ticket in tickets:
            res.append(ticket)

        if len(tickets) == 0 or len(res) > limit * offset:
            break

    return res


def get_defendant_to_reject(where=None):

    if not where:
        where = [Q()]
        where = reduce(operator.and_, where)

    defendants = Ticket.objects.filter(
        where,
        status='Open',
        priority__in=TODO_TICKET_PRIORITY_FILTERS,
        defendant__details__creationDate__lt=datetime.now() - timedelta(days=30)
    ).values_list('defendant', flat=True)
    rejected = set([k for k, v in Counter(defendants).iteritems() if v > 1])

    return rejected
