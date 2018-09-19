
from django.db import models


# http://stackoverflow.com/questions/3459843/auto-truncating-fields-at-max-length-in-django-charfields
class TruncatedCharField(models.CharField):
    """
        Hack for legacy Charfield. Use Textfield is a better solution
    """

    def get_prep_value(self, value):
        def unicode_truncate(data, length, encoding="utf-8"):
            encoded = data.encode(encoding)[:length]
            return encoded.decode(encoding, "ignore")

        value = super(TruncatedCharField, self).get_prep_value(value)
        if value:
            return unicode_truncate(value, self.max_length)
        return value
