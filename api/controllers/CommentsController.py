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
    Cerberus comments manager
"""

from functools import wraps
from time import mktime

from django.db.models import ObjectDoesNotExist
from django.forms.models import model_to_dict

from abuse.models import Comment, DefendantComment, Ticket, TicketComment, User
from worker import database


def check_comment(func):
    """ Check if comment is valid
    """
    @wraps(func)
    def check(*args, **kwargs):
        try:
            comment = Comment.objects.get(id=kwargs['comment_id'])
        except (ObjectDoesNotExist, ValueError):
            return 404, {'status': 'Not Found', 'code': 404, 'message': 'Comment not found'}

        if comment.user_id != kwargs['user_id']:
            return 403, {'status': 'Forbidden', 'code': 403, 'message': 'Comment not owned by user'}

        if kwargs.get('ticket_id') and not TicketComment.objects.filter(ticket=kwargs['ticket_id'], comment=kwargs['comment_id']).exists():
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Comment not associated to specified ticket'}

        if kwargs.get('defendant_id') and not DefendantComment.objects.filter(defendant=kwargs['defendant_id'], comment=kwargs['comment_id']).exists():
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Comment not associated to defendant ticket'}

        # OK, it's valid
        return func(*args, **kwargs)
    return check


def show(comment_id):
    """ Get Comment
    """
    try:
        comment = Comment.objects.get(id=comment_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Comment not found'}

    comment_dict = model_to_dict(comment)
    comment_dict['date'] = mktime(comment.date.timetuple())

    if comment_dict.get('user'):
        comment_dict['user'] = User.objects.get(id=comment_dict['user']).username

    return 200, comment_dict


def create(body, ticket_id=None, defendant_id=None, user_id=None):
    """ Create a comment
    """
    try:
        content = body.pop('comment')
    except KeyError:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing comment field in body'}

    comment = Comment.objects.create(comment=content, user_id=user_id)

    if ticket_id:
        TicketComment.objects.create(ticket_id=ticket_id, comment_id=comment.id)
        user = User.objects.get(id=user_id)
        ticket = Ticket.objects.get(id=ticket_id)
        database.log_action_on_ticket(
            ticket=ticket,
            action='add_comment',
            user=user
        )
    elif defendant_id:
        DefendantComment.objects.create(defendant_id=defendant_id, comment_id=comment.id)

    return show(comment.id)


@check_comment
def update(body, comment_id=None, ticket_id=None, user_id=None):
    """ Update comment
    """
    try:
        comment = Comment.objects.get(id=comment_id)
        content = body.pop('comment')
        comment.comment = content
        comment.save()

        if ticket_id:
            user = User.objects.get(id=user_id)
            ticket = Ticket.objects.get(id=ticket_id)
            database.log_action_on_ticket(
                ticket=ticket,
                action='update_comment',
                user=user
            )

    except KeyError:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing comment field in body'}

    return show(comment_id)


@check_comment
def delete(comment_id=None, ticket_id=None, defendant_id=None, user_id=None):
    """ Delete a comment
    """
    if ticket_id:
        TicketComment.objects.filter(ticket=ticket_id, comment=comment_id).delete()
        Comment.objects.filter(id=comment_id).delete()
        user = User.objects.get(id=user_id)
        ticket = Ticket.objects.get(id=ticket_id)
        database.log_action_on_ticket(
            ticket=ticket,
            action='delete_comment',
            user=user
        )
    elif defendant_id:
        DefendantComment.objects.filter(defendant=defendant_id, comment=comment_id).delete()
        Comment.objects.filter(id=comment_id).delete()

    return 200, {'status': 'OK', 'code': 200}
