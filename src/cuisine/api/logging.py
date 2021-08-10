from ..api import APIModule as API
from ..decorators import expose
from ..logging import LoggingContext


class LoggingAPI(API):

    def init(self):
        self.log = LoggingContext()

    @expose
    def info(self, message: str) -> None:
        self.log.info(message)

    @expose
    def error(self, message: str) -> None:
        self.log.error(message)


# EOF
