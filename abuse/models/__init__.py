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


from django.contrib.auth.models import User

from .defendant import Defendant, DefendantRevision, DefendantHistory, DefendantComment
from .history import History
from .misc import (
    ServiceAction,
    ServiceActionJob,
    Category,
    ApiRoute,
    Role,
    Operator,
    EmailFilter,
    EmailFilterTag,
    Resolution,
    AttachedDocument,
    Comment,
    Profile,
    AbusePermission,
    News,
    MailTemplate,
    Proof,
    TicketActionParams,
    TicketAction,
    TicketWorkflowPresetConfig,
    TicketWorkflowPreset,
    ItemScreenshotFeedback,
    ReportThreshold,
    MassContact,
    MassContactResult,
    StarredTicket,
    BusinessRules,
    BusinessRulesHistory,
)
from .provider import Provider
from .report import Report
from .reportitem import ReportItem
from .service import Service
from .tag import Tag
from .ticket import Ticket, TicketComment

assert AbusePermission
assert ApiRoute
assert AttachedDocument
assert BusinessRules
assert BusinessRulesHistory
assert Category
assert Comment
assert Defendant
assert DefendantComment
assert DefendantHistory
assert DefendantRevision
assert EmailFilter
assert EmailFilterTag
assert History
assert ItemScreenshotFeedback
assert MailTemplate
assert MassContact
assert MassContactResult
assert News
assert Operator
assert Profile
assert Proof
assert Provider
assert Report
assert ReportItem
assert ReportThreshold
assert Resolution
assert Role
assert Service
assert ServiceAction
assert ServiceActionJob
assert StarredTicket
assert Tag
assert Ticket
assert TicketAction
assert TicketActionParams
assert TicketComment
assert TicketWorkflowPreset
assert TicketWorkflowPresetConfig
assert User
