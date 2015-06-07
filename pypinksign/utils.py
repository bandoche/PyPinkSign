"""
Skeleton Helpers
"""

from __future__ import with_statement
from contextlib import closing
import codecs
import logging
import optparse
import os
import re
import stat
import sys


VALID_OPTION_NAME = re.compile("[a-z]([\w\d]*[a-z0-9])?", re.IGNORECASE)


def get_loggger(name):
    """Get the logger for the given name and assign an dummy handler to it.
    """
    logger = logging.getLogger(name)
    logger.addHandler(NullHandler())
    return logger


def vars_to_optparser(variables, parser=None):
    """Augments the parser with option to set value for the list of variables.
    """
    if parser is None:
        parser = optparse.OptionParser()

    for var in variables:
        if not VALID_OPTION_NAME.match(var.name):
            continue
        parser.add_option(
            "--%s" % var.name.lower().replace('_', '-'),
            dest=var.name,
            help=var.full_description,
            metavar=var.name.split('_')[-1].upper())
    return parser


def get_file_mode(path):
    """
    Return the mode of a file, the part usable with os.chmod
    """
    return stat.S_IMODE(os.stat(path)[stat.ST_MODE])


def insert_into_file(
    file_path, marker, text,
    marker_tag="-*-", keep_indent=True, keep_marker=True, encoding="UTF-8"):
    """Insert text into file at specific markers.

    eg, for a file "test.txt" with::

        foo
        # -*- Insert Here -*-
        baz

    `-*- Insert Here -*-` is the marker; anything can be added in front or
    after. `insert_into_file('test.txt', 'Insert Here', 'bar')` would result
    with::

        foo
        # -*- Insert Here -*-
        bar
        baz

    Arguments:

    - file_path:  file to insert content into.
    - marker:  Marker to look for in the file.
    - text (unicode):  text to insert in the file.
    - marker_tag:  text surrounding the marker.
    - keep_indent: Should it insert the text with the same marker indent.
    - keep_marker: Should the marker be removed.
    - encoding: file encoding.
    """
    marker_pattern = re.escape('%s %s %s' % (marker_tag, marker, marker_tag,))
    marker_re = re.compile(r"^(\s*).*%s.*$" % marker_pattern)
    edited = False
    new_content = []
    with closing(
        codecs.open(file_path, 'r', encoding=encoding)) as opened_file:
        for line in opened_file:
            match = marker_re.match(line)
            if match is None:
                new_content.append(line.rstrip('\n\r'))
                continue

            edited = True

            if keep_marker:
                new_content.append(line.rstrip('\n\r'))

            if keep_indent:
                indent = match.groups()[0]
                for text_line in text.splitlines():
                    new_content.append('%s%s' % (indent, text_line,))
            else:
                for text_line in text.splitlines():
                    new_content.append(text_line)

    if not edited:
        return

    with closing(
        codecs.open(file_path, 'w', encoding=encoding)) as opened_file:
        for line in new_content:
            opened_file.write('%s%s' % (line, os.linesep,))


class NullHandler(logging.Handler):
    """Dummy log handler.
    """

    def emit(self, record):
        """
        Doesn't do anything with record
        """


def prompt(prompt_):
    """Wrapper around the raw_input builtin function

    Will return unicode in Python 2 like in Python 3
    """
    result = raw_input(prompt_)
    try:
        return result.decode(sys.stdin.encoding)
    except AttributeError:
        return result
