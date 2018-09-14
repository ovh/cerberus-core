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

from flask import current_app as app
from mock import patch

from ...models import Category, Provider
from ...tests.setup import CerberusTest
from ...tasks.report import create_from_email


class ApiTestCase(CerberusTest):
    """
        Test case for API
    """
    def setUp(self):
        """
        """
        super(ApiTestCase, self).setUp()

        self.tester = app.test_client(self)

        self.static_endpoints = (
            '/api/emailTemplates/recipientsType',
            '/api/emailTemplates/languages',
            '/api/priorities/provider',
            '/api/priorities/ticket',
            '/api/defendants/top20',
            '/api/tickets/todo',
            '/api/admin/threshold',
            '/api/users/me',
            '/api/tags/types',
            '/api/emailTemplates',
            '/api/my-categories',
            '/api/notifications',
            '/api/mass-contact',
            '/api/resolutions',
            '/api/categories',
            '/api/my-tickets',
            '/api/dashboard',
            '/api/providers',
            '/api/profiles',
            '/api/monitor',
            '/api/toolbar',
            '/api/presets',
            '/api/reports',
            '/api/tickets',
            '/api/search',
            '/api/status',
            '/api/users',
            '/api/roles',
            '/api/news',
            '/api/tags'
        )

    def test_failed_logout(self):
        """
        """
        response = self.tester.post('/api/logout')
        self.assertEqual(response.status_code, 401)

    def test_static_get(self):

        response = self.tester.post(
            '/api/auth',
            data=json.dumps({'name': 'abuse.robot', 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        token = json.loads(response.get_data())['token']

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            with patch(*self.patch_getnotif):
                for endpoint in self.static_endpoints:
                    response = self.tester.get(
                        endpoint,
                        headers={'X-API-TOKEN': token},
                    )
                    self.assertEqual(response.status_code, 200)

    def test_globals(self):

        p, _ = Provider.get_or_create(email='starz_media@copyright-compliance.com')
        p.trusted = True
        p.save()

        with open('abuse/tests/samples/sample18', 'r') as file_d:
            content = file_d.read()
            with patch(*self.patch_enqueue_in), patch(*self.patch_enqueue):
                create_from_email(email_content=content)

        response = self.tester.post(
            '/api/auth',
            data=json.dumps({'name': 'abuse.robot', 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        token = json.loads(response.get_data())['token']

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            response = self.tester.get(
                '/api/dashboard',
                headers={'X-API-TOKEN': token},
            )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())

        self.assertEqual(1, response['reportsByCategory']['Copyright'])
        self.assertEqual(1, response['reportsByStatus']['Attached'])
        self.assertEqual(1, response['ticketsByStatus']['Open'])

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            response = self.tester.get(
                '/api/toolbar',
                headers={'X-API-TOKEN': token},
            )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())

        for k, v in response.iteritems():
            if not k == 'todoCount':
                self.assertEqual(0, v)
            else:
                self.assertEqual(1, v)

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            response = self.tester.get(
                '/api/defendants/top20',
                headers={'X-API-TOKEN': token},
            )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())
        self.assertEqual(1, response['report'][0]['count'])
        self.assertEqual('john.doe@example.com', response['report'][0]['email'])

    def test_admin(self):

        with open('abuse/tests/samples/sample18', 'r') as file_d:
            content = file_d.read()
            with patch(*self.patch_enqueue_in), patch(*self.patch_enqueue):
                create_from_email(email_content=content)

        response = self.tester.post(
            '/api/auth',
            data=json.dumps({'name': 'abuse.robot', 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        token = json.loads(response.get_data())['token']

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            response = self.tester.get(
                '/api/users',
                headers={'X-API-TOKEN': token},
            )
            self.assertEqual(response.status_code, 200)
            response = json.loads(response.get_data())

        self.assertEqual('abuse.robot', response[0]['username'])

        for profile in response[0]['profiles']:
            self.assertEqual('Expert', profile['profile'])

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            response = self.tester.get(
                '/api/categories',
                headers={'X-API-TOKEN': token},
            )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())

        for category in response:
            self.assertTrue(Category.objects.filter(**category).exists())

    def test_search(self):

        p, _ = Provider.get_or_create(email='starz_media@copyright-compliance.com')
        p.trusted = True
        p.save()

        with open('abuse/tests/samples/sample18', 'r') as file_d:
            content = file_d.read()
            with patch(*self.patch_enqueue_in), patch(*self.patch_enqueue):
                create_from_email(email_content=content)

        response = self.tester.post(
            '/api/auth',
            data=json.dumps({'name': 'abuse.robot', 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        token = json.loads(response.get_data())['token']

        params = {
            'paginate': {
                'currentPage': 1,
                'resultsPerPage': 10
            },
            'queryFields': [
                'id',
                'publicId',
                'category',
            ],
            'sortBy': {
                'creationDate': 1
            },
            'where': {
                'in': [{
                    'status': [
                        'Open',
                        'Paused',
                        'Answered',
                        'Alarm',
                        'WaitingAnswer',
                        'Reopened'
                    ]
                }]
            }
        }

        response = self.tester.get(
            '/api/search',
            query_string={'filters': json.dumps(params)},
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())

        self.assertEqual(1, response['ticketsCount'])
        self.assertEqual('Copyright', response['tickets'][0]['category'])
        self.assertNotIn('commentsCount', response['tickets'][0]['category'])

        publicId = response['tickets'][0]['publicId']

        # Filter with publicId
        params['where']['like'] = [{'publicId': [publicId]}]

        response = self.tester.get(
            '/api/search',
            query_string={'filters': json.dumps(params)},
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())
        self.assertEqual(1, response['ticketsCount'])

        # Invalid publicId
        params['where']['like'] = [{'publicId': 'AAAAAAAAAA'}]

        response = self.tester.get(
            '/api/search',
            query_string={'filters': json.dumps(params)},
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())
        self.assertEqual(0, response['ticketsCount'])

    def test_ticket(self):

        p, _ = Provider.get_or_create(email='starz_media@copyright-compliance.com')
        p.trusted = True
        p.save()

        with open('abuse/tests/samples/sample18', 'r') as file_d:
            content = file_d.read()
            with patch(*self.patch_enqueue_in), patch(*self.patch_enqueue):
                create_from_email(email_content=content)

        response = self.tester.post(
            '/api/auth',
            data=json.dumps({'name': 'abuse.robot', 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        token = json.loads(response.get_data())['token']

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            with patch(*self.patch_enqueue):
                response = self.tester.get(
                    '/api/tickets/1',
                    headers={'X-API-TOKEN': token},
                )
        self.assertEqual(response.status_code, 200)

        response = self.tester.get(
            'api/tickets/1/actions/list',
            headers={'X-API-TOKEN': token},
        )
        response = json.loads(response.get_data())
        self.assertEqual(1, len(response))
        self.assertEqual('default_action', response[0]['name'])

        response = self.tester.get(
            'api/tickets/1/items',
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)

    def test_admin_threshold(self):

        response = self.tester.post(
            '/api/auth',
            data=json.dumps({'name': 'abuse.robot', 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        token = json.loads(response.get_data())['token']

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            response = self.tester.get(
                '/api/admin/threshold/1337',
                headers={'X-API-TOKEN': token},
            )
        self.assertEqual(response.status_code, 404)

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            with patch(*self.patch_api_cache_delete):
                response = self.tester.post(
                    '/api/admin/threshold',
                    data=json.dumps({'category': 'Copyright', 'interval': 15, 'threshold': 15}),
                    headers={
                        'content-type': 'application/json',
                        'X-API-TOKEN': token
                    },
                )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())
        self.assertEqual(15, response['interval'])

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            response = self.tester.get(
                '/api/admin/threshold',
                headers={'X-API-TOKEN': token},
            )
        response = json.loads(response.get_data())
        self.assertEqual(len(response), 2)

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            response = self.tester.post(
                '/api/admin/threshold',
                data=json.dumps({'category': 'Spam', 'interval': 15, 'threshold': 15}),
                headers={
                    'content-type': 'application/json',
                    'X-API-TOKEN': token
                },
            )
        self.assertEqual(response.status_code, 400)

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            with patch(*self.patch_api_cache_delete):
                response = self.tester.post(
                    '/api/admin/threshold',
                    data=json.dumps({'category': 'Other', 'interval': 30, 'threshold': 15}),
                    headers={
                        'content-type': 'application/json',
                        'X-API-TOKEN': token
                    },
                )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())
        self.assertEqual(30, response['interval'])

        with patch(*self.patch_api_cache_get), patch(*self.patch_api_cache_set):
            response = self.tester.get(
                '/api/admin/threshold',
                headers={'X-API-TOKEN': token},
            )
        response = json.loads(response.get_data())
        self.assertEqual(len(response), 3)
