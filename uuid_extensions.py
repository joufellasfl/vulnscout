# -*- coding: utf-8 -*-
#
# Lightweight replacement for uuid_extensions.uuid7 used in tests.

import uuid


def uuid7(as_type: str = "str"):
    value = uuid.uuid4()
    if as_type == "str":
        return str(value)
    return value
