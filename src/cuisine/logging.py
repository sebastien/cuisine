from typing import Optional, Union, Callable, List, Any, Iterable

try:
    from colorama import Fore, Style
    RED = Fore.RED
    GREEN = Fore.GREEN
    BLUE = Fore.BLUE
    DIM = Style.DIM
    BRIGHT = Style.BRIGHT
    RESET = Style.RESET_ALL
except ImportError as e:
    RED = ""
    GREEN = ""
    BLUE = ""
    DIM = ""
    BRIGHT = ""
    RESET = ""

import sys
import json

LOGGING_BYTES = False
STRINGIFY_MAXSTRING = 80
STRINGIFY_MAXLISTSTRING = 20


def stringify(value):
    """Turns the given value in a user-friendly string that can be displayed"""
    if type(value) in (str, bytes) and len(value) > STRINGIFY_MAXSTRING:
        return f"{value[0:STRINGIFY_MAXSTRING]}…"
    elif type(value) in (list, tuple) and len(value) > 10:
        return f"[{', '.join([stringify(_) for _ in value[0:STRINGIFY_MAXLISTSTRING]])},…]"
    else:
        return str(value)


# TODO: We need to define how that works
def log_call(function, args, kwargs):
    """Logs the given function call"""
    function_name = function.__name__
    a = ", ".join([stringify(_) for _ in args] + [str(k) +
                                                  "=" + stringify(v) for k, v in kwargs.items()])
    log_debug("{0}({1})".format(function_name, a))


# TODO: The context should be tweakable, we should be able to apply a filter
class LoggingContext:

    def __init__(self):
        self.prompt: Callable[[], str] = lambda: ""
        self._formatters = [Formatter.Get()]

    @property
    def formatter(self):
        return self._formatters[-1]

    def push(self, formatter: Optional['Formatter'] = None):
        """Used to push a new formatter onto the stack"""
        # FIXME: May not be the best way to do it, see TMux
        self._formatters.append(formatter or NullFormatter.Get())
        return self

    def pop(self):
        self._formatters.pop()
        return self

    def dispatch(self, type: str, args: List[Any]):
        self.formatter.receive(self, type, args)

    def action(self, name: str,  *args: str):
        self.dispatch("action", [name] + [_ for _ in args])

    def result(self, value: Any, success=True):
        self.dispatch("result", [value, success])

    def error(self, message: str):
        self.dispatch("error", [message])

    def out(self, data: Union[str, bytes]):
        self.dispatch("out", [data])

    def info(self, data: Union[str, bytes]):
        self.dispatch("info", [data])

    def err(self, data: Union[str, bytes]):
        self.dispatch("err", [data])


# TODO: The formatting API is quite basic and ad-hoc for now,
# should be reworked.
class Formatter:

    SINGLETON: Optional['Formatter'] = None

    @classmethod
    def Get(cls) -> 'Formatter':
        if not cls.SINGLETON:
            cls.SINGLETON = cls()
        return cls.SINGLETON

    def __init__(self):
        self.active: Optional[LoggingContext] = None

    def write(self, line: str):
        sys.stdout.write(line)

    def receive(self, origin: LoggingContext, action: str, args: List[Any]):
        if origin != self.active:
            self.write(
                f"{BLUE}{DIM}═══{RESET}\t{BLUE}{origin.prompt()}{RESET}\n")
            self.active = origin
        if action == "out":
            self.write(DIM)
            self.block(args, "┆")
            self.write(RESET)
        elif action == "info":
            self.write(BLUE)
            self.block(args, "🛈")
            self.write(RESET)
        elif action == "err":
            self.write(RED)
            self.block(args, "⫼")
            self.write(RESET)
        elif action == "action" and args[0] == "command":
            self.write(
                f"{DIM}┌─●\t{BRIGHT}{' '.join(args[1:])}{RESET}\n")
        elif action == "result":
            self.write(
                f"{GREEN}{DIM}└─►\t{RESET}{GREEN}{json.dumps(args[0])}{RESET}\n")
        elif action == "error":
            self.write(
                f"{RED}{DIM}└─✕\t{RESET}{RED}{json.dumps(args[0])}{RESET}\n")
        else:
            self.write(
                f"{BLUE}{DIM}▹▹▹{RESET}\t{BLUE}{' '.join(stringify(_) for _ in args)}{RESET}\n")

    def block(self, data: Iterable[Any], char="|"):
        for item in data:
            if isinstance(item, str):
                self.lines(item.split("\n"), f"{char}\t")
            elif isinstance(item, bytes):
                self.lines(str(item, "utf8").split("\n"), f"{char}\t")
            else:
                self.write(f"{char}\t{repr(item)}\n")

    def lines(self, lines: List[str], prefix=""):
        last = len(lines) - 1
        for i, line in enumerate(lines):
            if i == last and not line.strip():
                continue
            print(f"{prefix}{line}")


class NullFormatter(Formatter):

    SINGLETON: Optional['Formatter'] = None

    def write(self, line: str):
        pass

    def receive(self, origin: LoggingContext, action: str, args: List[Any]):
        pass

# EOF
