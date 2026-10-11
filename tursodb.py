"""SentryFeed's connection to Turso: turso-serverless's sqlite3-style connection, with three
changes for a collector that talks to a database on the other side of the world:

- One HTTPS connection is kept open and reused, instead of a new connection (and a new TLS
  handshake, the step that most often timed out) for every statement.
- executemany sends rows BATCH_ROWS at a time instead of one request per row, so the daily
  refresh of CISA's list and EPSS scores is a few requests rather than thousands.
- One retry when Turso has dropped a stream for being idle, outside a transaction.

They override the library's internal hooks (Session._post, Connection._execute_stmt,
Connection.executemany), which is why its version is pinned in requirements.txt.
"""
import http.client
import json
import select
import time
import urllib.parse

import turso_serverless
from turso_serverless.connection import _classify_error
from turso_serverless.dbapi import _is_dml
from turso_serverless.protocol import ProtocolError, build_batch_step
from turso_serverless.session import Session, _parse_cursor_body, _server_error

Error = turso_serverless.Error

# Seconds to wait for Turso to connect or to send the next bytes of an answer; the library sets
# no limit, so a stalled connection would hang a page until Vercel stopped it.
TIMEOUT = 10
# A kept-open connection idle longer than this is replaced rather than reused: the server may
# have closed it, and a request lost on a closed connection can't safely be sent again.
IDLE_REUSE = 10
BATCH_ROWS = 200


class _KeepAliveSession(Session):
    """The library's session, sending every request over one kept-open HTTPS connection."""

    def __init__(self, url, auth_token=None):
        super().__init__(url, auth_token=auth_token)
        self._http = None
        self._http_for = None
        self._last_used = 0.0

    def _close_http(self):
        if self._http is not None:
            self._http.close()
        self._http = None

    def _usable(self, target):
        """Whether the open connection can carry the next request: same server, not idle for
        long, and not closed by the server (an idle socket with something to read has hit EOF)."""
        if self._http is None or self._http.sock is None or self._http_for != target:
            return False
        if time.monotonic() - self._last_used > IDLE_REUSE:
            return False
        return not select.select([self._http.sock], [], [], 0)[0]

    def _open(self, scheme, host, port):
        """A new connection. Connecting is tried twice: until it succeeds nothing has been sent,
        so a timed-out handshake can't have run a statement."""
        cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        for attempt in (1, 2):
            conn = cls(host, port, timeout=TIMEOUT)
            try:
                conn.connect()
                return conn
            except OSError:
                conn.close()
                if attempt == 2:
                    raise

    def _post(self, path, body):
        """Same contract as the library's _post: the response body, or ProtocolError (and the
        stream forgotten) for any failure, never re-sending a request that may have arrived."""
        url = f"{self._base_url}{path}"
        parts = urllib.parse.urlsplit(url)
        target = (parts.scheme, parts.hostname, parts.port)
        data = json.dumps(body, allow_nan=False).encode("utf-8")
        try:
            for attempt in (1, 2):
                reused = self._usable(target)
                if not reused:
                    self._close_http()
                    self._http, self._http_for = self._open(*target), target
                try:
                    self._http.request("POST", parts.path or "/", body=data, headers=self._headers())
                    break
                except (http.client.HTTPException, OSError):
                    # Failing while sending means the request never arrived whole, so the server
                    # can't have run it: on a reused connection (which the server may have
                    # closed), send it once more on a new one. A failure after this point, while
                    # waiting for the answer, is never retried: the statement may have run.
                    self._close_http()
                    if not (reused and attempt == 1):
                        raise
            resp = self._http.getresponse()
            raw = resp.read()
            self._last_used = time.monotonic()
            if resp.will_close:
                self._close_http()
        except (http.client.HTTPException, OSError) as e:
            self._close_http()
            self._reset_stream()
            raise ProtocolError(f"request to {url} failed: {e!r}") from None
        if resp.status != 200:
            self._reset_stream()
            message = None
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    message = next((parsed[k] for k in ("error", "message") if isinstance(parsed.get(k), str)), None)
            except ValueError:
                pass
            raise ProtocolError(f"HTTP status {resp.status}: {message}" if message else f"HTTP status {resp.status}")
        return raw

    def close(self):
        super().close()
        self._close_http()


class Connection(turso_serverless.Connection):
    def _execute_stmt(self, sql, params=None, named_params=None, want_rows=True):
        """One retry when Turso has dropped the stream for being idle (the local server does after
        about 15 seconds; Turso's cloud kept one for at least 6 minutes in testing). The retry runs
        on a fresh stream, and only when no transaction was open: then nothing was half-written and
        the statement simply never ran. Inside a transaction its uncommitted writes are gone, so
        the error is raised as before."""
        idle_retry_safe = not self.in_transaction
        try:
            return super()._execute_stmt(sql, params, named_params, want_rows)
        except turso_serverless.OperationalError as e:
            if not (idle_retry_safe and "stream has expired" in str(e)):
                raise
        return super()._execute_stmt(sql, params, named_params, want_rows)

    def executemany(self, sql, seq_of_parameters):
        """The library's executemany sends one request per row. This sends BATCH_ROWS rows per
        request, in the same implicit transaction. Within a batch each row runs only if the one
        before succeeded, and the first error is raised, so the caller rolls back as before."""
        self._ensure_open()
        if not _is_dml(sql):
            raise turso_serverless.ProgrammingError("executemany() requires a single DML statement")
        self._maybe_implicit_begin(sql)
        cur = self.cursor()
        total, steps = 0, []
        for parameters in seq_of_parameters:
            args, named = turso_serverless.Cursor._convert_params(parameters)
            condition = {"type": "ok", "step": len(steps) - 1} if steps else None
            steps.append(build_batch_step(sql, args=args, named_args=named, want_rows=False, condition=condition))
            if len(steps) == BATCH_ROWS:
                total += self._run_batch(steps)
                steps = []
        if steps:
            total += self._run_batch(steps)
        cur._rowcount = total
        return cur

    def _run_batch(self, steps):
        """Run the steps in one cursor request; returns the rows they changed. A last step that only
        runs outside a transaction tells us the transaction state, as the library's own requests do."""
        session = self._session
        probe = len(steps)
        try:
            raw = session._post("/v3/cursor", {"baton": session._baton,
                                               "batch": {"steps": [*steps, session._autocommit_probe_step()]}})
            cursor_resp, entries = _parse_cursor_body(raw)
        except ProtocolError as e:
            session._reset_stream()
            raise _classify_error(e) from None
        session._update_stream(cursor_resp.get("baton"), cursor_resp.get("base_url"))
        changed, error, probe_ran, probe_unreliable = 0, None, False, False
        for entry in entries:
            kind, step = entry.get("type"), entry.get("step")
            if kind == "step_begin" and step == probe:
                probe_ran = True
            elif kind == "step_end" and step != probe:
                changed += entry.get("affected_row_count") or 0
            elif kind == "step_error":
                if step == probe:
                    probe_unreliable = True
                elif error is None:
                    error = _server_error(entry.get("error"))
            elif kind == "error":
                error, probe_unreliable = error or _server_error(entry.get("error")), True
        if probe_unreliable:
            session._refresh_autocommit()
        else:
            session._autocommit = probe_ran
        if error is not None:
            raise _classify_error(error)
        return changed


def connect(url, auth_token=None):
    return Connection(_KeepAliveSession(url, auth_token=auth_token))
