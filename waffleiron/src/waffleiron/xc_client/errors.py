"""XC client error hierarchy."""

from __future__ import annotations


class XCError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class XCAuthError(XCError):
    pass


class XCNotFoundError(XCError):
    pass


class XCConflictError(XCError):
    pass


class XCRateLimitError(XCError):
    pass


class XCServerError(XCError):
    pass
