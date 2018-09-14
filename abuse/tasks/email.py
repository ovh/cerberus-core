
import base64
import hashlib
import mimetypes

from datetime import datetime

from django.utils import text as text_utils

from ..models import AttachedDocument, History, Ticket, User
from ..services import EmailService, StorageService
from ..services.email import EMAIL_VALID_CATEGORIES
from ..services.storage import StorageServiceException
from ..utils import text


def send_ticket_email(ticket_id=None, subject=None, body=None, category=None,
                      recipients=None, attachments=None,
                      attach_email_thread=False, user_id=None):

    ticket = Ticket.get(id=ticket_id)
    user = User.objects.get(id=user_id)

    category = category.title()
    if category not in EMAIL_VALID_CATEGORIES:
        raise ValueError('Invalid email category %s' % category)

    email_thread = None
    if attach_email_thread:
        email_thread = _get_email_thread_attachment(ticket, email_category='defendant')

    merged_attachments = _get_merged_attachments(ticket, attachments, email_thread)

    attachments = _fetch_attachments(
        attachments,
        merged_attachments,
        email_thread,
        attach_email_thread=attach_email_thread
    )

    for recipient in recipients:
        EmailService.send_email(
            ticket,
            recipient,
            subject,
            body,
            category,
            attachments=attachments,
        )
        History.log_ticket_action(
            ticket=ticket,
            action='send_email',
            user=user,
            email=recipient
        )


def _get_merged_attachments(ticket, attachments, email_thread):

    _attachments = []
    if attachments:
        _attachments.extend(attachments)

    if email_thread:
        _attachments.append(email_thread)

    _attachments = map(dict, set(map(lambda x: tuple(x.items()), _attachments)))
    sanitized = {}

    if _attachments:
        try:
            sanitized = _save_and_sanitize_attachments(
                ticket,
                _attachments,
            )
        except StorageServiceException:
            raise Exception('Error while uploading attachments')
        except KeyError:
            raise Exception('Missing or invalid params in attachments')

    return sanitized


def _save_and_sanitize_attachments(ticket, attachments):

    sanitized = {}

    for attachment in attachments:

        filetype = attachment['filetype']

        if attachment.get('content'):  # New attachment

            name = attachment['name']
            # new attachment content are encoded in base64 (coming from UX)
            content = base64.b64decode(attachment['content'])

            filename = text_utils.get_valid_filename(name)
            storage_filename = text.get_attachment_storage_filename(
                content=content,
                filename=filename
            )

            if ticket.attachments.filter(filename=storage_filename).exists():
                content = StorageService.read(storage_filename)
            else:
                StorageService.write(storage_filename, content)
                if ticket.attachments.filter(name=name).exists():
                    name = '{}_{}'.format(storage_filename[:4], name)

                ticket.attachments.add(AttachedDocument.create(
                    filename=storage_filename,
                    filetype=filetype,
                    name=name
                ))

            _hash = hashlib.sha256(attachment['content']).hexdigest()
            sanitized[(_hash, name)] = {
                'content': content,
                'content_type': filetype,
                'filename': name
            }

        elif attachment.get('filename'):  # Existing

            content = StorageService.read(attachment['filename'])
            sanitized[(attachment['filename'], attachment['name'])] = {
                'content': content,
                'content_type': filetype,
                'filename': attachment['name']
            }

    return sanitized


def _get_email_thread_attachment(ticket, email_category=None):

    _emails = EmailService.get_emails(ticket)
    emails = [email for email in _emails if email.category.lower() == email_category]

    content, filetype = text.get_email_thread_content(ticket, emails)

    name = 'ticket_{}_emails_{}{}'.format(
        ticket.publicId,
        datetime.strftime(datetime.now(), '%d-%m-%Y_%H-%M-%S'),
        mimetypes.guess_extension(filetype),
    )

    return {'filetype': filetype, 'content': base64.b64encode(content), 'name': name}


def _fetch_attachments(attachments, merged_attachments, email_thread, attach_email_thread=False):

    _attachments = []
    if attachments:
        for attach in attachments:
            if attach.get('content'):
                _hash = hashlib.sha256(attach['content']).hexdigest()
                try:
                    _attachments.append(merged_attachments[(_hash, attach['name'])])
                except KeyError:  # renamed
                    _attachments.append(
                        merged_attachments[(_hash, '{}_{}'.format(_hash[:4], attach['name']))]
                    )
            elif attach.get('filename'):
                _attachments.append(merged_attachments[(attach['filename'], attach['name'])])

    if attach_email_thread:
        _hash = hashlib.sha256(email_thread['content']).hexdigest()
        _attachments.append(merged_attachments[(_hash, email_thread['name'])])

    return _attachments
