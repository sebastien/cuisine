from typing import Generic, TypeVar, Optional, Union, Dict
import os

T = TypeVar("T")


class KeyValueStore(Generic[T]):

    def set(self, key: str, value: T) -> Optional[T]:
        pass

    def has(self, key: str) -> bool:
        pass

    def get(self, key: str) -> T:
        pass


class DictKeyValueStore(KeyValueStore[T]):

    def __init__(self, source: Optional[Dict[str, T]] = None):
        self.values: Dict[str, T] = source or {}

    def set(self, key: str, value: T) -> Optional[T]:
        previous = self.values.get(key)
        self.values[key] = value
        return previous

    def has(self, key: str) -> bool:
        return key in self.values

    def get(self, key: str) -> T:
        return self.values.get(str)


class EnvironKeyValueStore(KeyValueStore[str]):

    def __init__(self):
        pass

    def set(self, key: str, value: str) -> Optional[str]:
        previous = os.environ[key] if key in os.environ else None
        os.environ[key] = str(value)
        return previous

    def has(self, key: str) -> bool:
        return key in os.environ

    def get(self, key: str) -> Optiona[str]:
        return os.environ[key] if key in os.environ else None

# EO
