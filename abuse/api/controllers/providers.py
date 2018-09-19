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
    Providers manager
"""

import json
import operator
from urllib import unquote

from django.core.exceptions import FieldError
from django.db import IntegrityError
from django.db.models import ObjectDoesNotExist, ProtectedError, Q
from django.forms.models import model_to_dict
from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from ...models import Category, Provider, Tag


def get_providers(**kwargs):
    """ Get all providers in db
    """
    filters = {}

    if kwargs.get("filters"):
        try:
            filters = json.loads(unquote(unquote(kwargs["filters"])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex.message))
    try:
        limit = int(filters["paginate"]["resultsPerPage"])
        offset = int(filters["paginate"]["currentPage"])
    except KeyError:
        limit = 10
        offset = 1

    try:
        where = _generate_request_filter(filters)
    except (
        AttributeError,
        KeyError,
        IndexError,
        FieldError,
        SyntaxError,
        ValueError,
    ) as ex:
        raise BadRequest(str(ex.message))

    try:
        sort = ["-" + k if v < 0 else k for k, v in filters["sortBy"].iteritems()]
    except KeyError:
        sort = ["email"]

    if "queryFields" in filters:
        fields = filters["queryFields"]
    else:
        fields = [f.name for f in Provider._meta.fields]

    try:
        fields.remove("tags")
    except ValueError:
        pass

    try:
        count = Provider.filter(where).count()
        providers = (
            Provider.filter(where).values("email", *fields).order_by(*sort).distinct()
        )
        providers = providers[(offset - 1) * limit : limit * offset]
        len(providers)  # Force django to evaluate query now
    except (KeyError, FieldError, ValueError) as ex:
        raise BadRequest(str(ex.message))

    for provider in providers:
        provider.pop("apiKey", None)
        tags = Provider.get(email=provider["email"]).tags.all()
        provider["tags"] = [model_to_dict(tag) for tag in tags]

    return {"providers": list(providers), "providersCount": count}


def _generate_request_filter(filters):
    """ Generates filters from filter query string
    """
    where = [Q()]
    if "where" in filters and len(filters["where"]):
        keys = set(k for k in filters["where"])
        if "like" in keys:
            for i in filters["where"]["like"]:
                for key, val in i.iteritems():
                    field = key + "__icontains"
                    where.append(reduce(operator.or_, [Q(**{field: val[0]})]))
        where = reduce(operator.and_, where)
    else:
        where = reduce(operator.and_, where)
    return where


def show(provider_email):
    """ Get one provider
    """
    try:
        provider = Provider.get(email=provider_email)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Provider does not exist")

    provider = model_to_dict(provider)
    provider.pop("apiKey", None)
    provider["tags"] = [model_to_dict(tag) for tag in provider["tags"]]

    return provider


def create(body):
    """ Create provider
    """
    if "email" not in body:
        raise BadRequest("Email field required")
    if len(Provider.filter(email=body["email"])) > 1:
        raise BadRequest("Provider already exists")

    try:
        cat = None
        if body.get("defaultCategory"):
            cat = Category.get(name=body["defaultCategory"])
        body.pop("defaultCategory", None)
        body = {k: v for k, v in body.iteritems() if k in Provider.get_fields()}
        provider = Provider.create(defaultCategory=cat, **body)
        return show(provider.email)
    except (FieldError, IntegrityError, ObjectDoesNotExist) as ex:
        raise BadRequest(str(ex.message))


def update(prov, body):
    """ Update provider infos
    """
    try:
        provider = Provider.get(email=prov)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Provider does not exist")
    try:
        body = {k: v for k, v in body.iteritems() if k in Provider.get_fields()}
        cat = None
        if body.get("defaultCategory"):
            cat = Category.get(name=body["defaultCategory"])
        if "tags" in body and body["tags"] is not None:
            tags = [t["id"] for t in body["tags"]]
            provider.tags.clear()
            provider.tags.add(*tags)
            body.pop("tags")
        body.pop("defaultCategory", None)
        Provider.filter(pk=provider.pk).update(defaultCategory=cat, **body)
        provider = Provider.get(pk=provider.pk)
    except (KeyError, FieldError, IntegrityError, ObjectDoesNotExist) as ex:
        raise BadRequest(str(ex.message))
    return show(provider.email)


def destroy(prov):
    """ Remove provider
    """
    try:
        provider = Provider.filter(email=prov)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound("Provider not found")
    try:
        provider.delete()
        return {"message": "Provider successfully removed"}
    except ProtectedError:
        raise Forbidden("Provider still referenced in reports")


def get_provider_by_key(key):
    """ Return provider associated with API key
    """
    try:
        provider = Provider.get(apiKey=key)
        return provider
    except (ObjectDoesNotExist, TypeError, ValueError):
        pass
    return None


def get_priorities():
    """ Get provider priorities
    """
    return [{"label": p[0]} for p in Provider.PROVIDER_PRIORITY]


def add_tag(provider_email, body):
    """ Add provider tag
    """
    try:
        tag = Tag.get(**body)
        provider = Provider.get(email=provider_email)

        if provider.__class__.__name__ != tag.tagType:
            raise BadRequest("Invalid tag for provider")

        provider.tags.add(tag)
        provider.save()

    except (KeyError, FieldError, IntegrityError, ObjectDoesNotExist, ValueError):
        raise NotFound("Provider or tag not found")
    return show(provider.email)


def remove_tag(provider_email, tag_id):
    """ Remove defendant tag
    """
    try:
        tag = Tag.get(id=tag_id)
        provider = Provider.get(email=provider_email)

        if provider.__class__.__name__ != tag.tagType:
            raise BadRequest("Invalid tag for provider")

        provider.tags.remove(tag)
        provider.save()

    except (ObjectDoesNotExist, FieldError, IntegrityError, ValueError):
        raise NotFound("Provider or tag not found")
    return show(provider.email)
