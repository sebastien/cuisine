LOGGING_BYTES = False
STRINGIFY_MAXSTRING = 80
STRINGIFY_MAXLISTSTRING = 20


def info(*args, **kwargs):
    print("INFO", args, kwargs)


def error(*args, **kwargs):
    print("ERROR", args, kwargs)


def debug(message: str):
    print("DEBUG", message)


def log_string(message: str):
    """Ensures that the string is safe for logging"""
    return bytes(message, "UTF8") if LOGGING_BYTES else message


def stringify(value):
    """Turns the given value in a user-friendly string that can be displayed"""
    if type(value) in (str, bytes) and len(value) > STRINGIFY_MAXSTRING:
        return f"{value[0:STRINGIFY_MAXSTRING]}…"
    elif type(value) in (list, tuple) and len(value) > 10:
        return f"[{', '.join([stringify(_) for _ in value[0:STRINGIFY_MAXLISTSTRING]])},…]"
    else:
        return str(value)


def log_call(function, args, kwargs):
    """Logs the given function call"""
    function_name = function.__name__
    a = ", ".join([stringify(_) for _ in args] + [str(k) +
                                                  "=" + stringify(v) for k, v in kwargs.items()])
    log_debug("{0}({1})".format(function_name, a))

# EOF
