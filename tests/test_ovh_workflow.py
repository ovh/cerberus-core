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
    Unit tests for workers functions
"""

import os
from datetime import datetime, timedelta

from django.conf import settings
from mock import patch

from abuse.models import (ServiceAction, ContactedProvider, Report,
                          Provider, Resolution, Ticket, User, UrlStatus,
                          Service, Defendant, BusinessRules, BusinessRulesHistory)
from adapters.services.phishing.abstract import PingResponse
from factory.implementation import ImplementationFactory
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


class MockRedis(object):
    """
        Mimick a Redis object so unit tests can run
    """
    def __init__(self):
        self.redis = {}

    def set(self, key, *args):

        if key not in self.redis:
            self.redis[key] = []

    def delete(self, key):

        self.redis.pop(key, None)

    def exists(self, key):
        return key in self.redis

    def rpush(self, key, value):

        if key not in self.redis:
            self.redis[key] = [value]
        else:
            self.redis[key].append(value)

    def lrange(self, key, *args):

        if key not in self.redis:
            return []

        return self.redis[key]

    def lrem(self, key, value):
        self.redis[key].remove(value)


class TestWorkers(GlobalTestCase):
    """
        Unit tests for workers functions
    """
    def setUp(self):

        super(TestWorkers, self).setUp()
        self._samples = {}

        for root, dirs, files in os.walk(SAMPLES_DIRECTORY):
            for name in files:
                filename = root + '/' + name
                f = open(filename, 'r')
                self._samples[name] = f

    def tearDown(self):
        for k, v in self._samples.iteritems():
            v.close()

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_trusted(self, mock_rq):
        """
            Sample6 is a phishing report
        """
        from worker import report

        mock_rq.return_value = None
        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.last()
        self.assertEqual('Phishing', report.category.name)
        self.assertFalse(report.ticket)
        self.assertEqual('PhishToCheck', report.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_not_trusted(self, mock_rq):
        """
            Sample7 is a phishing report
        """
        from worker import report

        mock_rq.return_value = None
        sample = self._samples['sample7']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.last()
        self.assertEqual('Phishing', report.category.name)
        self.assertFalse(report.ticket)
        self.assertEqual('PhishToCheck', report.status)

        # test timeout
        from worker.report import archive_if_timeout
        report.status = 'New'
        report.save()
        archive_if_timeout(report_id=report.id)
        report = Report.objects.get(id=report.id)
        self.assertEqual('Archived', report.status)

    @patch('default.adapters.services.phishing.impl.DefaultPhishingService.ping_url')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_down(self, mock_rq, mock_ping):
        """
            Sample6 is a phishing report, now down items
        """
        from worker import report

        mock_rq.return_value = None
        mock_ping.return_value = PingResponse(100, '404', 'Not Found', 'Not Found', False)
        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.last()
        self.assertEqual('Phishing', report.category.name)
        self.assertTrue(report.ticket)
        self.assertEqual('Archived', report.status)
        self.assertEqual('Closed', report.ticket.status)
        self.assertEqual(1, ContactedProvider.objects.count())  # Because an email is sent

    @patch('rq.queue.Queue.enqueue')
    @patch('rq_scheduler.scheduler.Scheduler.schedule')
    @patch('default.adapters.services.phishing.impl.DefaultPhishingService.ping_url')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_timeout(self, mock_rq_enqueue_in, mock_ping, mock_rq_schedule, mock_rq_enqueue):
        """
            Test phishing workflow
        """
        from worker import report

        mock_rq_enqueue_in.return_value = None
        mock_ping.return_value = PingResponse(100, '404', 'Not Found', 'Not Found for test_phishing_timeout', False)
        mock_rq_schedule.return_value = FakeJob()
        mock_rq_enqueue.return_value = FakeJob()

        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        # Reopening ticket
        cerberus_report = Report.objects.last()
        cerberus_report.status = 'Attached'
        cerberus_report.ticket.status = 'WaitingAnswer'
        cerberus_report.ticket.snoozeDuration = 1
        cerberus_report.ticket.snoozeStart = datetime.now() - timedelta(days=1)
        cerberus_report.ticket.save()
        cerberus_report.save()

        from worker import ticket as ticket_func

        ticket_func.update_waiting()

        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Alarm', ticket.status)
        ticket_func.timeout(ticket.id)
        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Closed', ticket.status)
        self.assertEqual(settings.CODENAMES['fixed_customer'], ticket.resolution.codename)

        # Reopening ticket
        UrlStatus.objects.all().delete()
        mock_ping.return_value = PingResponse(0, '200', 'UP', 'UP for test_phishing_timeout', False)
        cerberus_report = Report.objects.last()
        cerberus_report.status = 'Attached'
        cerberus_report.ticket.status = 'WaitingAnswer'
        cerberus_report.ticket.snoozeDuration = 1
        cerberus_report.ticket.snoozeStart = datetime.now() - timedelta(days=1)
        cerberus_report.ticket.save()
        cerberus_report.save()

        ticket_func.update_waiting()

        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Alarm', ticket.status)
        ticket_func.timeout(ticket.id)
        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Closed', ticket.status)
        self.assertEqual(settings.CODENAMES['fixed'], ticket.resolution.codename)

    @patch('rq.queue.Queue.enqueue')
    @patch('rq_scheduler.scheduler.Scheduler.schedule')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_copyright_trusted_specific_workflow(self, mock_rq_enqueue_in, mock_rq_schedule, mock_rq_enqueue):
        """
            Test copyright workflow and timeout
        """
        from worker import report

        mock_rq_enqueue_in.return_value = None
        mock_rq_schedule.return_value = FakeJob()
        mock_rq_enqueue.return_value = FakeJob()

        sample = self._samples['sample18']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)
        cerberus_report = Report.objects.last()
        cerberus_report.reportItemRelatedReport.all().update(fqdnResolved='1.2.3.4')
        self.assertEqual('Attached', cerberus_report.status)
        self.assertTrue(cerberus_report.ticket)
        self.assertIn('report:copyright_trusted', cerberus_report.tags.all().values_list('name', flat=True))
        self.assertTrue(BusinessRulesHistory.objects.count())

        cerberus_report.status = 'Attached'
        cerberus_report.ticket.status = 'WaitingAnswer'
        cerberus_report.ticket.snoozeDuration = 1
        cerberus_report.ticket.snoozeStart = datetime.now() - timedelta(days=1)
        cerberus_report.ticket.save()
        cerberus_report.save()

        from worker import ticket as ticket_func

        ticket_func.update_waiting()

        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Alarm', ticket.status)
        ticket_func.timeout(ticket.id)
        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Closed', ticket.status)
        self.assertEqual(settings.CODENAMES['fixed'], ticket.resolution.codename)

        # Check if not trusted
        Report.objects.all().delete()
        Ticket.objects.all().delete()
        content = content.replace("Test-Magic-Smtp-Header: it's here", "")
        report.create_from_email(email_content=content, send_ack=False)
        cerberus_report = Report.objects.last()
        self.assertEqual('New', cerberus_report.status)

    @patch('rq.get_current_job')
    @patch('default.adapters.services.phishing.impl.DefaultPhishingService.ping_url')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_action(self, mock_rq, mock_ping, mock_current_job):
        """
            Test action functions
        """
        from worker import report

        mock_rq.return_value = None
        mock_ping.return_value = PingResponse(100, '404', 'Not Found', 'Not Found', False)
        mock_current_job.return_value = FakeJob()

        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        cerberus_report = Report.objects.last()
        cerberus_report.status = 'Attached'
        cerberus_report.ticket.status = 'WaitingAnswer'
        cerberus_report.ticket.save()
        cerberus_report.save()

        ip_addr = '8.8.8.8'
        resolution = Resolution.objects.get(codename='fixed')
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])
        service_action = ServiceAction.objects.all()[0]

        from worker import action

        # Success
        action.apply_if_no_reply(
            ticket_id=cerberus_report.ticket.id,
            action_id=service_action.id,
            ip_addr=ip_addr,
            resolution_id=resolution.id,
            user_id=user.id
        )

        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Alarm', ticket.status)

        # Fail
        action.apply_if_no_reply(
            ticket_id=cerberus_report.ticket.id,
            action_id=999999,
            ip_addr=ip_addr,
            resolution_id=resolution.id,
            user_id=user.id
        )

        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('ActionError', ticket.status)

        ticket.status = 'WaitingAnswer'
        ticket.save()

        action.apply_then_close(
            ticket_id=cerberus_report.ticket.id,
            action_id=service_action.id,
            ip_addr=ip_addr,
            resolution_id=resolution.id,
            user_id=user.id
        )
        ticket = Ticket.objects.get(id=cerberus_report.ticket.id)
        self.assertEqual('Closed', ticket.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_acns_specific_workflow(self, mock_rq):
        """
            Test copyright/acns specific workflow
        """
        from worker import report

        Provider.objects.create(email='broadgreenpictures@copyright-compliance.com', trusted=True)
        mock_rq.return_value = None
        sample = self._samples['acns']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()

        emails = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').get_emails(cerberus_report.ticket)
        self.assertEqual(2, len(emails))
        self.assertEqual('Archived', cerberus_report.status)
        self.assertTrue(cerberus_report.ticket.resolution)
        self.assertEqual('Closed', cerberus_report.ticket.status)

    # Now testing without specific workflow
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_trusted_no_workflow(self, mock_rq):
        """
            Sample6 is a trusted phishing report
        """
        from worker import report
        BusinessRules.objects.filter(name__icontains='phishing').delete()

        mock_rq.return_value = None
        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.last()
        self.assertEqual('Phishing', report.category.name)
        self.assertTrue(report.ticket)
        self.assertEqual('Attached', report.status)
        self.assertEqual('Open', report.ticket.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_report_not_trusted_no_workflow(self, mock_rq):
        """
            Sample7 is not a trusted phishing report
        """
        from worker import report
        BusinessRules.objects.filter(name__icontains='phishing').delete()

        mock_rq.return_value = None
        sample = self._samples['sample7']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        self.assertEqual(1, Report.objects.count())
        report = Report.objects.last()
        self.assertEqual('Phishing', report.category.name)
        self.assertFalse(report.ticket)
        self.assertEqual('New', report.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_acns_specific_no_workflow(self, mock_rq):
        """
            Test copyright/acns specific workflow
        """
        from worker import report
        BusinessRules.objects.filter(name__icontains='acns').delete()

        Provider.objects.create(email='broadgreenpictures@copyright-compliance.com', trusted=True)
        mock_rq.return_value = None
        sample = self._samples['acns']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()

        self.assertEqual('Attached', cerberus_report.status)
        self.assertEqual('Open', cerberus_report.ticket.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_acns_specific_no_workflow_2(self, mock_rq):
        """
            Test copyright/acns specific with no workflow
        """
        from worker import report
        BusinessRules.objects.all().delete()

        Provider.objects.create(email='broadgreenpictures@copyright-compliance.com', trusted=False)
        mock_rq.return_value = None
        sample = self._samples['acns']
        content = sample.read()
        report.create_from_email(email_content=content)
        cerberus_report = Report.objects.last()

        self.assertEqual('New', cerberus_report.status)
        self.assertFalse(cerberus_report.ticket)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_phishing_trusted_provider(self, mock_rq):
        """
        """
        from worker import report

        mock_rq.return_value = None

        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        cerberus_report = Report.objects.last()
        self.assertEqual('Phishing', cerberus_report.category.name)
        self.assertFalse(cerberus_report.ticket)
        self.assertEqual('PhishToCheck', cerberus_report.status)

        sample = self._samples['sample7']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=False)

        cerberus_report = Report.objects.last()
        self.assertEqual('Phishing', cerberus_report.category.name)
        self.assertFalse(cerberus_report.ticket)
        self.assertEqual('PhishToCheck', cerberus_report.status)

    @patch('rq.queue.Queue.enqueue')
    @patch('rq_scheduler.scheduler.Scheduler.schedule')
    @patch('default.adapters.services.phishing.impl.DefaultPhishingService.ping_url')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_clearly_identified_phishing(self, mock_rq_enqueue_in, mock_ping, mock_rq_schedule, mock_rq_enqueue):
        """
            Test when phishing is clearly identified (PingResponse last parameter is True)
        """
        from worker import report

        mock_rq_enqueue_in.return_value = None
        mock_ping.return_value = PingResponse(0, '200', 'OK', 'OK', True)
        mock_rq_schedule.return_value = FakeJob()
        mock_rq_enqueue.return_value = FakeJob()

        sample = self._samples['sample6']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)

        cerberus_report = Report.objects.last()
        self.assertEqual('Phishing', cerberus_report.category.name)
        self.assertTrue(cerberus_report.ticket)
        self.assertEqual('WaitingAnswer', cerberus_report.ticket.status)
        self.assertEqual('Attached', cerberus_report.status)
        emails = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').get_emails(cerberus_report.ticket)
        self.assertEqual(2, len(emails))
        email = emails[0]
        self.assertIn('http://www.example.com/phishing.html', email.body)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_tovalidate_invalid(self, mock_rq):
        """
            Check if report is archived when invalidate
        """
        from worker import report

        mock_rq.return_value = None

        sample = self._samples['sample23']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)
        cerberus_report = Report.objects.last()
        self.assertEqual('ToValidate', cerberus_report.status)
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])
        report.validate_without_defendant(report_id=cerberus_report.id, user_id=user.id)
        cerberus_report = Report.objects.last()
        self.assertEqual('Archived', cerberus_report.status)
        self.assertTrue(cerberus_report.ticket)
        self.assertEqual('Closed', cerberus_report.ticket.status)

    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_tovalidate_valid(self, mock_rq):
        """
            Check if report is attached if validate
        """
        from worker import report

        mock_rq.return_value = None

        # Let's create a valid defendant/service first
        sample = self._samples['sample2']
        content = sample.read()
        report.create_from_email(email_content=content)

        # Now create ToValidate report
        sample = self._samples['sample23']
        content = sample.read()
        report.create_from_email(email_content=content, send_ack=True)
        cerberus_report = Report.objects.last()
        self.assertEqual('ToValidate', cerberus_report.status)

        # Consider operator add items on this report via UX
        cerberus_report.service = Service.objects.last()
        cerberus_report.defendant = Defendant.objects.last()
        cerberus_report.save()

        # Now reparse
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])
        report.validate_with_defendant(report_id=cerberus_report.id, user_id=user.id)
        cerberus_report = Report.objects.last()
        self.assertEqual('Attached', cerberus_report.status)
        self.assertTrue(cerberus_report.ticket)
        self.assertEqual('Open', cerberus_report.ticket.status)

    @patch('rq.queue.Queue.enqueue')
    @patch('utils.utils.redis', new_callable=MockRedis)
    @patch('utils.utils.get_ips_from_fqdn')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_tovalidate_cloudflare_request(self, mock_rq, mock_utils, mock_redis, mock_enqueue):
        """
            Test Cloudflare request workflow
        """
        from worker import report

        mock_rq.return_value = None
        mock_utils.return_value = ['103.21.244.1']
        mock_enqueue.return_value = FakeJob()

        # Create report
        sample = self._samples['sample23']
        content_to_request = sample.read()
        report.create_from_email(email_content=content_to_request, send_ack=True)
        cerberus_report = Report.objects.last()
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

        # Apply cdn request workflow
        report.cdn_request(
            report_id=cerberus_report.id,
            user_id=user.id,
            domain_to_request='www.cdnproxy-protected-domain.com'
        )

        cerberus_report = Report.objects.last()
        self.assertEqual('Attached', cerberus_report.status)
        self.assertTrue(cerberus_report.ticket)

        cerberus_ticket = Ticket.objects.last()
        emails = ImplementationFactory.instance.get_singleton_of(
            'MailerServiceBase'
        ).get_emails(
            cerberus_ticket
        )
        self.assertEqual(cerberus_ticket.treatedBy, user)
        self.assertEqual(1, len(emails))
        recipient = emails[0].sender

        # Fake Cloudflare response and parse response
        sample = self._samples['sample24']
        content = sample.read()
        content = content.replace('ticket+toreplace@example.com', recipient)
        report.create_from_email(email_content=content, send_ack=True)

        # Now ticket have a defendant/service
        cerberus_report = Report.objects.last()
        cerberus_ticket = Ticket.objects.last()
        self.assertTrue(cerberus_report.service)
        self.assertTrue(cerberus_report.defendant)

        # Try use cache for new request
        report.create_from_email(email_content=content_to_request, send_ack=True)
        cerberus_report = Report.objects.last()
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

        report.cdn_request(
            report_id=cerberus_report.id,
            user_id=user.id,
            domain_to_request='www.cdnproxy-protected-domain.com'
        )

        cerberus_report = Report.objects.last()
        self.assertEqual('Attached', cerberus_report.status)
        self.assertTrue(cerberus_report.service)
        self.assertTrue(cerberus_report.defendant)

    @patch('rq.queue.Queue.enqueue')
    @patch('utils.utils.redis', new_callable=MockRedis)
    @patch('utils.utils.get_ips_from_fqdn')
    @patch('rq_scheduler.scheduler.Scheduler.enqueue_in')
    def test_tovalidate_cloudflare_request_2(self, mock_rq, mock_utils, mock_redis, mock_enqueue):
        """
            Testing two consecutive TovVlidate Cloudflare case
        """
        from worker import report

        mock_rq.return_value = None
        mock_utils.return_value = ['103.21.244.1']
        mock_enqueue.return_value = FakeJob()

        # Create report
        sample = self._samples['sample23']
        content_to_request = sample.read()

        for _ in xrange(2):
            report.create_from_email(email_content=content_to_request, send_ack=True)
            cerberus_report = Report.objects.last()
            user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

            # Apply cdn request workflow
            report.cdn_request(
                report_id=cerberus_report.id,
                user_id=user.id,
                domain_to_request='www.cdnproxy-protected-domain.com'
            )

        cerberus_ticket = Ticket.objects.last()
        emails = ImplementationFactory.instance.get_singleton_of(
            'MailerServiceBase'
        ).get_emails(
            cerberus_ticket
        )
        self.assertEqual(cerberus_ticket.treatedBy, user)
        self.assertEqual(1, len(emails))
        self.assertEqual(2, cerberus_ticket.reportTicket.count())
        recipient = emails[0].sender

        # Fake Cloudflare response and parse response
        sample = self._samples['sample24']
        content = sample.read()
        content = content.replace('ticket+toreplace@example.com', recipient)
        report.create_from_email(email_content=content, send_ack=True)

        # Now ticket have a defendant/service
        cerberus_report = Report.objects.last()
        cerberus_ticket = Ticket.objects.last()
        self.assertTrue(cerberus_report.service)
        self.assertTrue(cerberus_report.defendant)

        # Try use cache for new request
        report.create_from_email(email_content=content_to_request, send_ack=True)
        cerberus_report = Report.objects.last()
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

        report.cdn_request(
            report_id=cerberus_report.id,
            user_id=user.id,
            domain_to_request='www.cdnproxy-protected-domain.com'
        )

        cerberus_report = Report.objects.last()
        self.assertEqual('Attached', cerberus_report.status)
        self.assertTrue(cerberus_report.service)
        self.assertTrue(cerberus_report.defendant)
