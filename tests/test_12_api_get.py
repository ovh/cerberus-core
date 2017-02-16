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
    Functional tests for Cerberus API
"""
import json

from django.conf import settings
from mock import patch

from tests import GlobalTestCase

SAMPLES_DIRECTORY = 'tests/samples'


class FakeJob(object):
    """
        Fake rq job for mock
    """
    def __init__(self):
        self.id = 42
        self.is_finished = True
        self.result = True


class ApiTestCase(GlobalTestCase):
    """
        Test case for API
    """
    def setUp(self):
        """
        """
        super(ApiTestCase, self).setUp()

        from api.api import APP
        APP.config['DEBUG'] = True
        APP.config['TESTING'] = True

        self.tester = APP.test_client(self)
        self.static_endpoints = (
            '/api/admin/threshold',
            '/api/categories',
            '/api/dashboard',
            '/api/defendants/top20',
            '/api/emailTemplates',
            '/api/emailTemplates/languages',
            '/api/emailTemplates/recipientsType',
            '/api/mass-contact',
            '/api/monitor',
            '/api/my-categories',
            '/api/my-tickets',
            '/api/news',
            '/api/notifications',
            '/api/presets',
            '/api/priorities/provider',
            '/api/priorities/ticket',
            '/api/profiles',
            '/api/providers',
            '/api/reports',
            '/api/resolutions',
            '/api/roles',
            '/api/search',
            '/api/status',
            '/api/tags',
            '/api/tags/types',
            '/api/tickets',
            '/api/tickets/todo',
            '/api/toolbar',
            '/api/users',
            '/api/users/me',
        )

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_static_get(self, mock_rq):

        mock_rq.return_value = None

        response = self.tester.post(
            '/api/auth',
            data=json.dumps({'name': settings.GENERAL_CONFIG['bot_user'], 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        token = json.loads(response.get_data())['token']

        for endpoint in self.static_endpoints:
            response = self.tester.get(
                endpoint,
                headers={'X-API-TOKEN': token},
            )
            self.assertEqual(response.status_code, 200)
