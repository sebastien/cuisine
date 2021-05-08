from pathlib import Path
from typing import List, Type, Tuple, Iterable, Callable
from ..decorators import IS_EXPOSED
from typing import Any
try:
    from ._stub import API
except ImportError as e:
    API = Any
import inspect
import importlib.util


class APIModule:
    """Defines the base class for Cuisine API modules. The given API is
    the stub, which is then implemented by the `cuisine.api._impl.API`
    class."""

    def __init__(self, api: API):
        self.api = api


def introspect() -> Iterable[Tuple[str, str, str, Callable]]:
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
                if value is APIModule or not (inspect.isclass(value) and issubclass(value, APIModule)):
                    continue
                for method_name, method in ((_, getattr(value, _)) for _ in dir(value) if not _.startswith("_")):
                    if not hasattr(method, IS_EXPOSED):
                        continue
                    yield (module_full_name, class_name, method_name, method)


def toSource(implementation=False, name: str = "API") -> Iterable[str]:
    """Generates the interface (stub) and the corresponding implementation
    of the flat-namespaces Cuisine API by introspecting the different API
    modules within the `cuisine.api` module."""
    # In this sad world, people prefer spaces to tabs
    tab = "     "
    data = list(introspect())
    if implementation:
        yield "from .._stub import API as APIInterface"
        yield f"class {name}(APIInterface):"
    else:
        yield f"class {name}:"
    if implementation:
        yield f"\n{tab}def __init__(self):"
        for module_name in sorted(set(_[0] for _ in data)):
            local_name = module_name.replace(".", "_")
            yield f"{tab}{tab}import {module_name} as {local_name}"
        for module_name, class_name in sorted(set((_[0], _[1]) for _ in data)):
            local_module_name = module_name.replace(".", "_")
            yield f"{tab}{tab}self._{class_name.replace('APIModule','').lower()} = {local_module_name}.{class_name}(self)"
    for class_name, method_name, method in sorted(set((_[1], _[2], _[3]) for _ in data)):
        # We erase the leading type
        sig = inspect.signature(method)
        sig_str = str(sig).replace(": cuisine.api.API", "")
        yield f"\n{tab}def {method_name}{sig_str}:"
        yield f"{tab}{tab}\"\"\"{method.__doc__}\"\"\""
        if not implementation:
            yield f"{tab}{tab}raise NotImplementedError"
        else:
            args = ", ".join(_ for _ in sig.parameters)
            yield f"{tab}{tab}return self._{class_name.replace('API', '').lower()}.{method_name}({args})"
    yield "\n# EOF"


# EOF
