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
from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from ...models import Comment, DefendantComment, Ticket, History, TicketComment, User


def check_comment(func):
    """ Check if comment is valid
    """

    @wraps(func)
    def check(*args, **kwargs):
        try:
            comment = Comment.get(id=kwargs["comment_id"])
        except (ObjectDoesNotExist, ValueError):
            raise NotFound("Comment not found")

        if comment.user_id != kwargs["user_id"]:
            raise Forbidden("Comment not owned by user")

        if kwargs.get("ticket_id"):
            existing = TicketComment.filter(
                ticket=kwargs["ticket_id"], comment=kwargs["comment_id"]
            ).exists()
            if not existing:
                raise BadRequest("Comment not associated to specified ticket")

        if kwargs.get("defendant_id"):
            existing = DefendantComment.filter(
                defendant=kwargs["defendant_id"], comment=kwargs["comment_id"]
            ).exists()
            if not existing:
                raise BadRequest("Comment not associated to defendant ticket")

        # OK, it's valid
        return func(*args, **kwargs)

    return check


def show(comment_id):
    """ Get Comment
    """
    try:
        comment = Comment.get(id=comment_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Comment not found")

    comment_dict = model_to_dict(comment)
    comment_dict["date"] = mktime(comment.date.timetuple())

    if comment_dict.get("user"):
        comment_dict["user"] = User.objects.get(id=comment_dict["user"]).username

    return comment_dict


def create(body, ticket_id=None, defendant_id=None, user_id=None):
    """ Create a comment
    """
    try:
        content = body.pop("comment")
    except KeyError:
        raise BadRequest("Missing comment field in body")

    comment = Comment.create(comment=content, user_id=user_id)

    if ticket_id:
        TicketComment.create(ticket_id=ticket_id, comment_id=comment.id)
        user = User.objects.get(id=user_id)
        ticket = Ticket.get(id=ticket_id)
        History.log_ticket_action(ticket=ticket, action="add_comment", user=user)
    elif defendant_id:
        DefendantComment.create(defendant_id=defendant_id, comment_id=comment.id)

    return show(comment.id)


@check_comment
def update(body, comment_id=None, ticket_id=None, user_id=None):
    """ Update comment
    """
    try:
        comment = Comment.get(id=comment_id)
        content = body.pop("comment")
        comment.comment = content
        comment.save()

        if ticket_id:
            user = User.objects.get(id=user_id)
            ticket = Ticket.get(id=ticket_id)
            History.log_ticket_action(ticket=ticket, action="update_comment", user=user)

    except KeyError:
        raise BadRequest("Missing comment field in body")

    return show(comment_id)


@check_comment
def delete(comment_id=None, ticket_id=None, defendant_id=None, user_id=None):
    """ Delete a comment
    """
    if ticket_id:
        TicketComment.filter(ticket=ticket_id, comment=comment_id).delete()
        Comment.filter(id=comment_id).delete()
        user = User.objects.get(id=user_id)
        ticket = Ticket.get(id=ticket_id)
        History.log_ticket_action(ticket=ticket, action="delete_comment", user=user)
    elif defendant_id:
        DefendantComment.filter(defendant=defendant_id, comment=comment_id).delete()
        Comment.filter(id=comment_id).delete()

    return {"message": "Comment successfully deleted"}
