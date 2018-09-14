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
    Define common functions for
    `cerberus.controllers.scheduling.TicketSchedulingAlgorithmBase`
    implementations
"""

import operator

from django.db.models import Q

from ..constants import TICKET_FILTER_MAPPING
from ....models import AbusePermission, User

USER_FILTERS_BEGINNER_PRIORITY = ('Low', 'Normal')


def get_treated_by_filters(user):
    """
        Returns ordered `abuse.models.Ticket` treatedBy filters list
    """
    users = list(set(User.objects.all().values_list('username', flat=True)))
    others_users = [username for username in users if username != user.username]

    treated_by_filters = [
        {
            'treatedBy__username': user.username,
        },
        {
            'treatedBy__username__in': others_users,
        },
        {
            'treatedBy': None,
        },
    ]
    return treated_by_filters


def get_user_filters(user):
    """
        Returns `django.db.models.query.QuerySet` filters based on allowed category for given user
    """
    where = [Q()]
    user_specific_where = []
    abuse_permissions = AbusePermission.objects.filter(user=user.id)

    for perm in abuse_permissions:
        if perm.profile.name == 'Expert':
            user_specific_where.append(Q(category=perm.category))
        elif perm.profile.name == 'Advanced':
            user_specific_where.append(Q(category=perm.category, confidential=False))
        elif perm.profile.name == 'Beginner':
            user_specific_where.append(Q(
                priority__in=USER_FILTERS_BEGINNER_PRIORITY,
                category=perm.category,
                confidential=False,
                escalated=False,
                moderation=False
            ))

    if user_specific_where:
        user_specific_where = reduce(operator.or_, user_specific_where)
        where.append(user_specific_where)
    else:
        # If no category allowed
        where.append(Q(category=None))

    return where


def get_generic_filters(filters):
    """
        Returns `django.db.models.query.QuerySet` filters based on request query filters
    """

    where = [Q()]
    # Generates Django query filter
    if filters.get('where'):
        keys = set(k for k in filters['where'])
        if 'in' in keys:
            for param in filters['where']['in']:
                for key, val in param.iteritems():
                    field = reduce(lambda a, kv: a.replace(*kv), TICKET_FILTER_MAPPING, key)
                    where.append(reduce(operator.or_, [Q(**{field: i}) for i in val]))
        if 'like' in keys:
            like = []
            for param in filters['where']['like']:
                for key, val in param.iteritems():
                    field = reduce(lambda a, kv: a.replace(*kv), TICKET_FILTER_MAPPING, key)
                    field = field + '__icontains'
                    like.append(Q(**{field: val[0]}))
            if like:
                where.append(reduce(operator.or_, like))

    return where
