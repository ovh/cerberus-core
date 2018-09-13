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
    Unit tests for action service default implementation
"""

from datetime import datetime

from ...models import ServiceAction, Ticket
from ...services.action import ActionService
from ...services.action.base import ActionServiceException

from ...tests.setup import CerberusTest


class TestDefaultActionImpl(CerberusTest):
    """
        Unit tests for action service
    """
    def setUp(self):
        self._ticket = Ticket.objects.create(
            publicId='AAAAAAAAAA',
            category_id='Spam',
            creationDate=datetime.now(),
        )

    def test_apply_action_on_service(self):
        """
            Test apply_action_on_service
        """
        result = ActionService.apply_action_on_service(
            self._ticket, ServiceAction.objects.last()
        )
        self.assertEqual('ok', result.status)
        self.assertRaises(ActionServiceException, lambda: ActionService.apply_action_on_service(self._ticket, 9999))
        self.assertRaises(ActionServiceException, lambda: ActionService.apply_action_on_service(123456, 9999))

    def test_list_actions_for_ticket(self):
        """
            Test list_actions_for_ticket
        """
        actions = ActionService.list_actions_for_ticket(self._ticket)
        self.assertEqual(1, len(actions))
        self.assertEqual('VPS', actions[0].module)
