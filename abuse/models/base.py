from django.db import models


class CerberusModel(models.Model):
    """ Base class for Cerberus """

    class Meta:

        abstract = True

    @classmethod
    def get_fields(cls):
        """
            Returns model field names
        """
        return [f.name for f in cls._meta.fields]

    @classmethod
    def get(cls, *args, **kwargs):
        """
            Syntastic sugar for django "get" objects's method
        """
        return cls.objects.get(*args, **kwargs)

    @classmethod
    def get_or_create(cls, *args, **kwargs):
        """
            Syntastic sugar for django "get_or_create" objects's method
        """
        return cls.objects.get_or_create(*args, **kwargs)

    @classmethod
    def create(cls, *args, **kwargs):
        """
            Syntastic sugar for django "create" objects's method
        """
        return cls.objects.create(*args, **kwargs)

    @classmethod
    def filter(cls, *args, **kwargs):
        """
            Syntastic sugar for django "filter" objects's method
        """
        return cls.objects.filter(*args, **kwargs)

    @classmethod
    def exclude(cls, *args, **kwargs):
        """
            Syntastic sugar for django "exclude" objects's method
        """
        return cls.objects.exclude(*args, **kwargs)

    @classmethod
    def all(cls):
        """
            Syntastic sugar for django "all" objects's method
        """
        return cls.objects.all()

    @classmethod
    def first(cls):
        """
            Syntastic sugar for django "first" objects's method
        """
        return cls.objects.first()

    @classmethod
    def last(cls):
        """
            Syntastic sugar for django "last" objects's method
        """
        return cls.objects.last()

    @classmethod
    def count(cls):
        """
            Syntastic sugar for django "count" objects's method
        """
        return cls.objects.count()

    @classmethod
    def raw(cls, *args, **kwargs):
        """
            Syntastic sugar for django "raw" objects's method
        """
        return cls.objects.raw(*args, **kwargs)
