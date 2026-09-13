"""TransportApi — the only network surface (spec §6, §7).  verify() never
enters it.  POSTs canonical JSON to the configured registry origin only; no
redirects are followed and no URLs found in artifacts are resolved.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from .errors import ERROR_CODES, SunlightError
from .ids import new_id
from .jcs import jcs
from .strictjson import parse_strict_json

BODY_CAP = 32 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RegistryTransport:
    def __init__(
        self,
        origin: str,
        bearer: str,
        connect_timeout_ms: int = 5000,
        read_timeout_ms: int = 10000,
        request_id=None,
    ):
        self.origin = origin
        self.bearer = bearer
        self.read_timeout_s = max(1, read_timeout_ms) / 1000.0
        self.request_id = request_id
        self._opener = urllib.request.build_opener(_NoRedirect)

    def rpc(self, method: str, params, req_id: str | None = None):
        request_id = (
            req_id
            or (self.request_id() if self.request_id else None)
            or new_id("slq")
        )
        req = {"v": "sunlight.rpc/1", "id": request_id, "method": method, "params": params}
        body = jcs(req)
        if len(body) > BODY_CAP:
            raise SunlightError("BODY_LIMIT")

        url = self.origin.rstrip("/") + "/v1/rpc"
        http_req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.bearer}",
            },
            method="POST",
        )
        try:
            res = self._opener.open(http_req, timeout=self.read_timeout_s)
            raw = res.read(BODY_CAP + 1)
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(BODY_CAP + 1)
            except Exception:
                raise SunlightError("NETWORK_ERROR", cause=e) from e
        except Exception as e:
            raise SunlightError("NETWORK_ERROR", cause=e) from e

        try:
            parsed = parse_strict_json(raw)
        except Exception as e:
            raise SunlightError("NETWORK_ERROR", cause=ValueError("unparseable response")) from e
        if not isinstance(parsed, dict):
            raise SunlightError("NETWORK_ERROR", cause=ValueError("non-object response"))

        if "error" in parsed and parsed.get("v") is None:
            raise self._to_error(parsed["error"])
        if parsed.get("ok") is True:
            return parsed.get("result")
        if parsed.get("ok") is False:
            raise self._to_error(parsed.get("error"))
        raise SunlightError("NETWORK_ERROR", cause=ValueError("malformed response"))

    @staticmethod
    def _to_error(err) -> SunlightError:
        code = err.get("code") if isinstance(err, dict) else None
        head = err.get("head") if isinstance(err, dict) else None
        if not isinstance(head, dict) or "seq" not in head or "hash" not in head:
            head = None
        return SunlightError(code if code in ERROR_CODES else "NETWORK_ERROR", head=head)
