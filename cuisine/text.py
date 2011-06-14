# -*- coding: utf-8 -*-
"""
    cuisine.text
    ~~~~~~~~~~~~

    Helper functions for working with strings.

    :copyright: (c) 2011 by Sebastien Pierre, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""

__all__ = ["line", "normalize", "nospace", "ensure_lines", "replace_lines",
           "strip_margin"]

import operator
import os
import re


def line(text, pred):
    """Returns the first line that matches the given predicate.

    :param unicode text: a blob to lookup the line in.
    :param pred: a predicate which checks if the line
                 is the one we need.
    """
    for line in text.splitlines():
        if pred(line):
            return line
    return ""


def normalize(text, replace=" "):
    """Converts multiple whitespace characters (tabs, spaces, newlines)
    to a single `replace` character and strips the resulting text.

    >>> normalize("foo\\n\\t    bar  baz   ")
    'foo bar baz'
    >>> normalize("foo        bar baz", replace="#")
    'foo#bar#baz'

    :param unicode text: a string to normalize.
    :param unicode replace: a character to replace whitespace with.
    """
    return re.sub(r"\s+", replace, text).strip()


def nospace(text):
    """An alias for ``normalize(text, replace="")``.

    >>> nospace("foo       bar")
    'foobar'
    """
    return normalize(text, replace="")


def replace_lines(text, old, new, cmp=operator.eq, key=lambda x: x):
    """Replaces lines equal to `old` with `new`, returning the modified
    text blob and the number of performed replacements.

    :param unicode text: a blob to process.
    :param unicode old: a line to be replaced.
    :param unicode new: replacement line.
    :param cmp: a function which takes too lines and returns ``True``
                if they're equal and ``False`` otherwise.
    :param key: a function which pre-processes the lines before
                comparison.
    """
    result, count = [], 0

    for line in text.splitlines():
        if cmp(key(line), key(old)):
            result.append(new)
            count += 1
        else:
            result.append(line)

    return os.linesep.join(result), count


def ensure_lines(text, *lines):
    """Ensures a list of lines is present in the text blob. If any of
    the given lines is missing -- it's appended to the bottom of the
    blob.

    >>> ensure_lines("foo\\nbar", "foo", "baz")
    'foo\\nbar\\nbaz'

    :param unicode text: a blob to lookup the lines in.
    :param lines: a list of lines to ensure.
    """
    result = text.splitlines()
    for line in lines:
        if os.linesep in line:
            raise ValueError("line separator found in: %r" % line)

        if line not in result:
            result.append(line)
    return os.linesep.join(result)


def strip_margin(text, margin="|"):
    """TODO: why this is useful?"""
    result = []
    for line in text.splitlines():
        try:
            _, line = line.split(margin, 1)
        except ValueError:
            pass
        else:
            result.append(line)
    return os.path.join(result)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
