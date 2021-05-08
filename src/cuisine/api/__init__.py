from pathlib import Path
from typing import List, Type, Tuple, Iterable, Callable
from ..decorators import IS_EXPOSED
import inspect
import importlib.util


class API:
    PREFIX = ""
    SUFFIX = ""

    def __init__(self):
        pass

    def run(self, command: str) -> 'CommandOutput':
        pass


def introspect_api(api: Type[API]) -> List[str]:
    """Introspects the contents of an API class, returning a list of symbols
    defined."""


def introspect() -> Iterable[Tuple[str, str, str, Callable]]:
    api_classes: List[Type[API]] = []
    for child in Path(__file__).parent.iterdir():
        if child.name.endswith(".py") and not child.name.startswith("_"):
            module_name = child.name.split('.', 1)[0]
            module_full_name = f"cuisine.api.{module_name}"
            # We need to use importlib as we don't want to change the namespace
            spec = importlib.util.spec_from_file_location(
                module_full_name, child)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for class_name, value in ((_, getattr(module, _)) for _ in dir(module)):
                if value is API or not (inspect.isclass(value) and issubclass(value, API)):
                    continue
                for method_name, method in ((_, getattr(value, _)) for _ in dir(value) if not _.startswith("_")):
                    if not hasattr(method, IS_EXPOSED):
                        continue
                    yield (module_full_name, class_name, method_name, method)


def toSource(name: str = "API", implementation=False) -> Iterable[str]:
    # In this sad world, people prefer spaces to tabs
    tab = "     "
    data = list(introspect())
    if implementation:
        for module_name in sorted(set(_[0] for _ in data)):
            local_name = module_name.replace(".", "_")
            yield f"import {module_name} as {local_name}"
    yield f"class {name}:"
    if implementation:
        yield f"\n{tab}def __init__(self):"
        for module_name, class_name in sorted(set((_[0], _[1]) for _ in data)):
            local_module_name = module_name.replace(".", "_")
            yield f"{tab}{tab}self._{class_name.replace('API','').lower()} = {local_module_name}.{class_name}()"
    for class_name, method_name, method in sorted(set((_[1], _[2], _[3]) for _ in data)):
        # We erase the leading type
        sig = str(inspect.signature(method)).replace(": cuisine.api.API", "")
        yield f"\n{tab}def {method_name}{sig}:"
        yield f"{tab}{tab}\"\"\"{method.__doc__}\"\"\""
        if not implementation:
            yield f"{tab}{tab}raise NotImplementedError"
        else:
            yield f"{tab}{tab}return self._{class_name.replace('API', '').lower()}.{method_name}(*args, **kwargs)"
    yield "\n# EOF"


# EOF
