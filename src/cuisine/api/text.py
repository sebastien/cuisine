# =============================================================================
#
# TEXT PROCESSING
#
# =============================================================================

def text_detect_eol(text):
    # FIXME: Should look at the first line
    if text.find("\r\n") != -1:
        return WINDOWS_EOL
    elif text.find("\n") != -1:
        return UNIX_EOL
    elif text.find("\r") != -1:
        return MAC_EOL
    else:
        return "\n"


def text_get_line(text, predicate):
    """Returns the first line that matches the given predicate."""
    for line in text.split("\n"):
        if predicate(line):
            return line
    return ""


def text_normalize(text):
    """Converts tabs and spaces to single space and strips the text."""
    return RE_SPACES.sub(" ", text).strip()


def text_nospace(text):
    """Converts tabs and spaces to single space and strips the text."""
    return RE_SPACES.sub("", text).strip()


def text_replace_line(text, old, new, find=lambda old, new: old == new, process=lambda _: _):
    """Replaces lines equal to 'old' with 'new', returning the new
    text and the count of replacements.

    Returns: (text, number of lines replaced)

    `process` is a function that will pre-process each line (you can think of
    it as a normalization function, by default it will return the string as-is),
    and `find` is the function that will compare the current line to the
    `old` line.

    The finds the line using `find(process(current_line), process(old_line))`,
    and if this matches, will insert the new line instead.
    """
    res = []
    replaced = 0
    eol = text_detect_eol(text)
    for line in text.split(eol):
        if find(process(line), process(old)):
            res.append(new)
            replaced += 1
        else:
            res.append(line)
    return eol.join(res), replaced


def text_replace_regex(text, regex, new, **kwargs):
    """Replace lines that match with the regex returning the new text

    Returns: text

    `kwargs` is for the compatibility with re.sub(),
    then we can use flags=re.IGNORECASE there for example.
    """
    res = []
    eol = text_detect_eol(text)
    for line in text.split(eol):
        res.append(re.sub(regex, new, line, **kwargs))
    return eol.join(res)


def text_ensure_line(text, *lines):
    """Ensures that the given lines are present in the given text,
    otherwise appends the lines that are not already in the text at
    the end of it."""
    eol = text_detect_eol(text)
    res = list(text.split(eol))
    if res[0] == '' and len(res) == 1:
        res = list()
    for line in lines:
        assert line.find(eol) == - \
            1, "No EOL allowed in lines parameter: " + repr(line)
        found = False
        for l in res:
            if l == line:
                found = True
                break
        if not found:
            res.append(line)
    return eol.join(res)


def text_strip_margin(text, margin="|"):
    """Will strip all the characters before the left margin identified
    by the `margin` character in your text. For instance

    ```
                    |Hello, world!
    ```

    will result in

    ```
    Hello, world!
    ```
    """
    res = []
    eol = text_detect_eol(text)
    for line in text.split(eol):
        l = line.split(margin, 1)
        if len(l) == 2:
            _, line = l
            res.append(line)
    return eol.join(res)


def text_template(text, variables):
    """Substitutes '${PLACEHOLDER}'s within the text with the
    corresponding values from variables."""
    template = string.Template(text)
    return template.safe_substitute(variables)


