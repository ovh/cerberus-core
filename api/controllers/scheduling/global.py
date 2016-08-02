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

from django.db.models import Count, Q

from abuse.models import Ticket
from api.controllers.scheduling import common
from api.controllers.scheduling.abstract import TicketSchedulingAlgorithmBase

FLAT_TODO_TICKET_STATUS_FILTERS = ('ActionError', 'Answered', 'Alarm', 'Reopened', 'Open')
TODO_TICKET_STATUS_FILTERS = (['ActionError'], ['Answered'], ['Alarm', 'Reopened'], ['Open'])
TODO_TICKET_DEFAULT_STATUS = ('ActionError', 'Answered', 'Alarm', 'Reopened', 'Open')
TODO_TICKET_PRIORITY_FILTERS = ('High', 'Normal', 'Low')
GLOBAL_TICKET_STATUS = ('ActionError', 'Answered', 'Alarm', 'Reopened', 'Open')
TICKET_FIELDS = [fld.name for fld in Ticket._meta.fields]


class GlobalSchedulingAlgorithm(TicketSchedulingAlgorithmBase):
    """
        Class defining standard `abuse.models.Ticket` scheduling algorithm
    """
    def count(self, **kwargs):

        if kwargs.get('where'):
            where = kwargs['where']
            return Ticket.objects.filter(where, status__in=GLOBAL_TICKET_STATUS).order_by('id').distinct().count()
        else:
            return Ticket.objects.filter(status__in=GLOBAL_TICKET_STATUS).order_by('id').distinct().count()

    def get_tickets(self, user=None, **kwargs):
        """
            Returns available `abuse.models.Ticket` according to scheduling algorithm

            Tickets selections:

            By priority of ticket status  (see TODO_TICKET_STATUS_FILTERS)
                By priority of ticket priorities (see TODO_TICKET_PRIORITY_FILTERS)
                    By user, others then treatedBy nobody

            Special case for 'Critical', it comes before all
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
        order_by = ['modificationDate']

        if filters.get('onlyUnassigned'):
            where.append(Q(treatedBy=None))
            treated_by_filters = [{'treatedBy': None}]
        else:
            treated_by_filters = common.get_treated_by_filters(user)

        # Aggregate all filters
        where = reduce(operator.and_, where)

        nb_record = Ticket.objects.filter(
            where,
            status__in=TODO_TICKET_DEFAULT_STATUS
        ).distinct().count()

        res = []
        ids = set()

        for ticket_status in TODO_TICKET_STATUS_FILTERS:
            if ticket_status == ['Open']:
                order_by.append('-reportTicket__tags__level')

            for filters in treated_by_filters:  # Only for Critical
                tickets = get_specific_filtered_todo_tickets(where, ids, 'Critical', ticket_status, filters, order_by, limit, offset)
                ids.update([t['id'] for t in tickets])
                res.extend(tickets)
                if len(res) > limit * offset:
                    return res[(offset - 1) * limit:limit * offset], nb_record

            if Ticket.objects.filter(where, ~Q(id__in=ids), status__in=FLAT_TODO_TICKET_STATUS_FILTERS, priority='Critical').count():
                continue

            for priority in TODO_TICKET_PRIORITY_FILTERS:
                for filters in treated_by_filters:

                    tickets = get_specific_filtered_todo_tickets(where, ids, priority, ticket_status, filters, order_by, limit, offset)
                    ids.update([t['id'] for t in tickets])
                    res.extend(tickets)
                    if len(res) > limit * offset:
                        return res[(offset - 1) * limit:limit * offset], nb_record

        return res[(offset - 1) * limit:limit * offset], nb_record


def get_specific_filtered_todo_tickets(where, ids, priority, status, treated_by, order_by, limit, offset):
    """
        Returns a list of `abuse.models.Ticket` dict-mapping based on multiple filters
    """
    return Ticket.objects.filter(
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
