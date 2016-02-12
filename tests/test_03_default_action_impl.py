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

from django.test import TestCase

from abuse.models import ServiceAction, Ticket
from adapters.services.action.abstract import ActionServiceException
from default.adapters.services.action.impl import DefaultActionService


class GlobalTestCase(TestCase):
    """
        Global setUp for tests
    """
    def setUp(self):
        self._ticket = Ticket.objects.create(
            publicId='AAAAAAAAAA',
            category_id='Spam',
            creationDate=datetime.now(),
        )
        self._action = ServiceAction.objects.create(
            name='default_action',
            module='VPS',
            level='1',
        )
        self._impl = DefaultActionService()

    def tearDown(self):
        pass


class TestDefaultActionImpl(GlobalTestCase):
    """
        Unit tests for action service
    """
    def test_apply_action_on_service(self):
        """
            Test apply_action_on_service
        """
        result = self._impl.apply_action_on_service(self._ticket, self._action)
        self.assertEqual('ok', result.status)
        self.assertRaises(ActionServiceException, lambda: self._impl.apply_action_on_service(self._ticket, 9999))
        self.assertRaises(ActionServiceException, lambda: self._impl.apply_action_on_service(123456, 9999))

    def test_list_actions_for_ticket(self):
        """
            Test list_actions_for_ticket
        """
        actions = self._impl.list_actions_for_ticket(self._ticket)
        self.assertEqual(1, len(actions))
        self.assertEqual('VPS', actions[0].module)

    def test_get_action_for_timeout(self):
        """
            Test get_action_for_timeout
        """
        action = self._impl.get_action_for_timeout(self._ticket)
        self.assertEqual('1', action.level)
        self.assertEqual('VPS', action.module)
        ServiceAction.objects.all().delete()
        action = self._impl.get_action_for_timeout(self._ticket)
        self.assertFalse(action)
