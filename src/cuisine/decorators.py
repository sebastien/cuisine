import types
import functools

IS_EXPOSED = "cuisine_is_exposed"


def dispatch(prefix=None, multiple=False):
    """Dispatches the current function to specific implementation. The `prefix`
    parameter indicates the common option prefix, and the `select_[option]()`
    function will determine the function suffix.

    For instance the package functions are defined like this:

    ```
    @dispatch("package")
    def package_ensure(...):
            ...
    def package_ensure_apt(...):
            ...
    def package_ensure_yum(...):
            ...
    ```

    and then when a user does

    ```
    cuisine.select_package("yum")
    cuisine.package_ensure(...)
    ```

    then the `dispatch` function will dispatch `package_ensure` to
    `package_ensure_yum`.

    If your prefix is the first word of the function name before the
    first `_` then you can simply use `@dispatch` without parameters.
    """
    def dispatch_wrapper(function, prefix=prefix):
        def wrapper(*args, **kwargs):
            function_name = function.__name__
            _prefix = prefix or function_name.split("_")[0].replace(".", "_")
            select = env_get(f"CUISINE_OPTION_{_prefix.upper()}")
            assert select, f"No option defined for: {_prefix.upper()}, call select_{prefix.lower().replace('.','_')} (<YOUR OPTION>) to set it"
            function_name = function.__name__ + "_" + select
            specific = eval(function_name)
            if specific:
                if type(specific) == types.FunctionType:
                    if multiple and args and isinstance(args[0], list):
                        rest = args[1:]
                        return [specific(_, *rest, **kwargs) for _ in args[0]]
                    else:
                        return specific(*args, **kwargs)
                else:
                    raise Exception(f"Function expected for: {function_name}")
            else:
                raise Exception(
                    f"Function variant not defined: {function_name}")
        # We copy name and docstring
        functools.update_wrapper(wrapper, function)
        return wrapper
    if type(prefix) == types.FunctionType:
        return dispatch_wrapper(prefix, None)
    else:
        return dispatch_wrapper


def logged(message=None):
    """Logs the invoked function name and arguments."""
    # TODO: Options - prevent sub @logged to output anything
    # TODO: Message - allow to specify a message
    # TODO: Category - read/write/exec as well as mode
    # [2013-10-28T10:18:32] user@host [sudo|user] [R/W] cuinine.function(xx,xxx,xx) [time]
    # [2013-10-28T10:18:32] user@host [sudo|user] [!] Exception
    def logged_wrapper(function, message=message):
        def wrapper(*args, **kwargs):
            log_call(function, args, kwargs)
            return function(*args, **kwargs)
        # We copy name and docstring
        functools.update_wrapper(wrapper, function)
        return wrapper
    if type(message) == types.FunctionType:
        return logged_wrapper(message, None)
    else:
        return logged_wrapper


def requires(*commands: str):
    """Decorator that captures requirement metdata for operations."""
    # TODO: Implement that
    def decorator(f):
        return f
    return decorator


def expose(f):
    setattr(f, IS_EXPOSED, True)
    return f

# EOF
