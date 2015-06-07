"""
Basic Template system for project pinksign,
similar to the template part of PasteScript but without any dependencies.

"""

from pinksign.core import (
    PinkSign, Var, Bool, FileNameKeyError, TemplateKeyError
)
from pinksign.utils import insert_into_file
