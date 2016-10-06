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
    Defined common functions for `api.controllers.scheduling.TicketSchedulingAlgorithmBase` implementations
"""

import operator

from django.db.models import Q

from abuse.models import AbusePermission, User

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
        Returns `django.db.models.query.QuerySet` filters depending on allowed category for given user
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

    if len(user_specific_where):
        user_specific_where = reduce(operator.or_, user_specific_where)
        where.append(user_specific_where)
    else:
        # If no category allowed
        where.append(Q(category=None))

    return where
