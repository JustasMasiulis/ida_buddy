"""IdbError and the protocol-code -> process exit-code mapping. No ida_* imports."""

from . import protocol

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_NO_SESSION = 3
EXIT_AMBIGUOUS = 4
EXIT_NOT_READY = 5
EXIT_TIMEOUT = 6
EXIT_UNAUTHORIZED = 7

NO_SESSION = "NO_SESSION"
AMBIGUOUS = "AMBIGUOUS"

_CODE_EXIT = {
    NO_SESSION: EXIT_NO_SESSION,
    AMBIGUOUS: EXIT_AMBIGUOUS,
    protocol.BAD_REQUEST: EXIT_ERROR,
    protocol.UNAUTHORIZED: EXIT_UNAUTHORIZED,
    protocol.UNKNOWN_CMD: EXIT_USAGE,
    protocol.BAD_ARGS: EXIT_USAGE,
    protocol.BAD_ADDRESS: EXIT_ERROR,
    protocol.NOT_FOUND: EXIT_ERROR,
    protocol.IDA_ERROR: EXIT_ERROR,
    protocol.NOT_READY: EXIT_NOT_READY,
    protocol.TIMEOUT: EXIT_TIMEOUT,
    protocol.INTERNAL: EXIT_ERROR,
}


class IdbError(Exception):
    """Carries a protocol code so both the worker (-> error envelope) and the
    client (-> exit code) can act on it uniformly."""

    def __init__(self, code, message, data=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_error(self, req_id):
        return protocol.build_error(req_id, self.code, self.message, self.data)


def exit_code_for(code) -> int:
    return _CODE_EXIT.get(code, EXIT_ERROR)
