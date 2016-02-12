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
import shutil

from django.conf import settings
from mock import patch

from abuse.models import Category, Report
from api.api import APP
from tests import GlobalTestCase

APP.config['DEBUG'] = True
APP.config['TESTING'] = True
SAMPLES_DIRECTORY = 'tests/samples'


class ApiTestCase(GlobalTestCase):
    """
        Test case for API
    """
    def test_failed_logout(self):
        """
        """
        tester = APP.test_client(self)
        response = tester.post('/api/logout')
        self.assertEqual(response.status_code, 401)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_globals(self, mock_rq):

        mock_rq.return_value = None

        from worker import report

        with open('tests/samples/sample3', 'r') as file_d:
            content = file_d.read()

        report.create_from_email(email_content=content, send_ack=False)
        self.assertEqual(1, Report.objects.count())
        self._cerberus_report = Report.objects.all()[:1][0]
        self._cerberus_ticket = self._cerberus_report.ticket

        tester = APP.test_client(self)
        response = tester.post(
            '/api/auth',
            data=json.dumps({'name': settings.GENERAL_CONFIG['bot_user'], 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        self.assertEqual(response.status_code, 200)
        token = json.loads(response.get_data())['token']

        response = tester.get(
            '/api/dashboard',
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())

        self.assertEqual(1, response['reportsByCategory']['Copyright'])
        self.assertEqual(1, response['reportsByStatus']['Attached'])
        self.assertEqual(1, response['ticketsByStatus']['Open'])

        response = tester.get(
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

        response = tester.get(
            '/api/defendants/top20',
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())
        self.assertEqual(1, response['report'][0]['count'])
        self.assertEqual('john.doe@example.com', response['report'][0]['email'])

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_admin(self, mock_rq):

        mock_rq.return_value = None

        from worker import report

        with open('tests/samples/sample3', 'r') as file_d:
            content = file_d.read()

        report.create_from_email(email_content=content, send_ack=False)
        self.assertEqual(1, Report.objects.count())
        self._cerberus_report = Report.objects.all()[:1][0]
        self._cerberus_ticket = self._cerberus_report.ticket

        tester = APP.test_client(self)
        response = tester.post(
            '/api/auth',
            data=json.dumps({'name': settings.GENERAL_CONFIG['bot_user'], 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        self.assertEqual(response.status_code, 200)
        token = json.loads(response.get_data())['token']

        response = tester.get(
            '/api/users',
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())

        self.assertEqual(settings.GENERAL_CONFIG['bot_user'], response[0]['username'])

        for profile in response[0]['profiles']:
            self.assertEqual('Expert', profile['profile'])

        response = tester.get(
            '/api/categories',
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())

        for category in response:
            self.assertTrue(Category.objects.filter(**category).exists())

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_search(self, mock_rq):

        mock_rq.return_value = None

        from worker import report

        with open('tests/samples/sample3', 'r') as file_d:
            content = file_d.read()

        report.create_from_email(email_content=content, send_ack=False)
        self.assertEqual(1, Report.objects.count())
        self._cerberus_report = Report.objects.all()[:1][0]
        self._cerberus_ticket = self._cerberus_report.ticket

        tester = APP.test_client(self)
        response = tester.post(
            '/api/auth',
            data=json.dumps({'name': settings.GENERAL_CONFIG['bot_user'], 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        self.assertEqual(response.status_code, 200)
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

        response = tester.get(
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

        response = tester.get(
            '/api/search',
            query_string={'filters': json.dumps(params)},
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())
        self.assertEqual(1, response['ticketsCount'])

        # Invalid publicId
        params['where']['like'] = [{'publicId': 'AAAAAAAAAA'}]

        response = tester.get(
            '/api/search',
            query_string={'filters': json.dumps(params)},
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.get_data())
        self.assertEqual(0, response['ticketsCount'])

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_ticket(self, mock_rq):

        mock_rq.return_value = None

        from worker import report

        with open('tests/samples/sample3', 'r') as file_d:
            content = file_d.read()

        report.create_from_email(email_content=content, send_ack=False)
        self.assertEqual(1, Report.objects.count())
        self._cerberus_report = Report.objects.all()[:1][0]
        self._cerberus_ticket = self._cerberus_report.ticket

        tester = APP.test_client(self)
        response = tester.post(
            '/api/auth',
            data=json.dumps({'name': settings.GENERAL_CONFIG['bot_user'], 'password': 'test'}),
            headers={'content-type': 'application/json'},
        )
        self.assertEqual(response.status_code, 200)
        token = json.loads(response.get_data())['token']

        response = tester.get(
            '/api/tickets/1',
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)

        response = tester.get(
            'api/tickets/1/actions/list',
            headers={'X-API-TOKEN': token},
        )
        response = json.loads(response.get_data())
        self.assertEqual(1, len(response))
        self.assertEqual('default_action', response[0]['name'])

        response = tester.get(
            'api/tickets/1/items',
            headers={'X-API-TOKEN': token},
        )
        self.assertEqual(response.status_code, 200)

    def test_clean(self):
        shutil.rmtree(settings.GENERAL_CONFIG['email_storage_dir'], ignore_errors=True)
