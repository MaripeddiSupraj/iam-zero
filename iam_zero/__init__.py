import os
import sys
import re

os.environ.setdefault("GRPC_VERBOSITY", "NONE")
os.environ.setdefault("GRPC_TRACE", "")

_GRPC_NOISE = re.compile(
    r"(absl::InitializeLog|alts_credentials|ALTS creds|E0000|WARNING: All log messages)"
)


class _StderrFilter:
    def __init__(self, stream):
        self._stream = stream

    def write(self, msg):
        if not _GRPC_NOISE.search(msg):
            self._stream.write(msg)

    def flush(self):
        self._stream.flush()

    def fileno(self):
        return self._stream.fileno()


sys.stderr = _StderrFilter(sys.stderr)

__version__ = "0.1.0"
