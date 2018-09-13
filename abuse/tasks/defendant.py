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
    Defendant tasks for Cerberus
"""

from ..models import Defendant, DefendantHistory, DefendantRevision
from ..services.crm import CRMService


def refresh_defendant_infos(defendant_id=None):
    """
        Update `abuse.models.Defendant`'s revision
    """
    defendant = Defendant.get(id=defendant_id)

    fresh_infos = CRMService.get_customer_infos(defendant.customerId)
    fresh_infos.pop('customerId', None)

    if DefendantRevision.filter(**fresh_infos).count():
        revision = DefendantRevision.filter(
            **fresh_infos
        ).last()
    else:
        revision = DefendantRevision.create(**fresh_infos)
        DefendantHistory.create(defendant=defendant, revision=revision)

    defendant.details = revision
    defendant.save()
