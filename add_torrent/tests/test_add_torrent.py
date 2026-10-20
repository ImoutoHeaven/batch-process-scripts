import importlib.util
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


@pytest.fixture
def client(monkeypatch):
    script = Path(__file__).resolve().parents[1] / "add-torrent.py"
    spec = importlib.util.spec_from_file_location("add_torrent", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr("builtins.input", lambda _: "test-user")
    monkeypatch.setattr(module.getpass, "getpass", lambda _: "test-password")
    return module


@pytest.fixture
def api():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, body, cookie=False):
            self.send_response(status)
            if cookie:
                self.send_header("Set-Cookie", "QBT_SID_9095=test-session; Path=/")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.headers.get("Cookie") == "QBT_SID_9095=test-session":
                self.respond(200, b"v5.2.3.10")
            else:
                self.respond(403, b"Forbidden")

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if self.path == "/api/v2/auth/login":
                assert body == b"username=test-user&password=test-password"
                status, response = self.server.login_result
                self.respond(status, response, cookie=response != b"Fails.")
            else:
                self.server.upload = (self.path, self.headers.get("Cookie"), body)
                self.respond(*self.server.add_result)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.login_result = (204, b"")
    server.add_result = (200, b'{"added_torrent_ids":["test-hash"],"failure_count":0,"pending_count":0,"success_count":1}')
    server.address = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("login_result,add_result", [
    ((204, b""), (200, b'{"added_torrent_ids":["test-hash"],"failure_count":0,"pending_count":0,"success_count":1}')),
    ((200, b"Ok."), (200, b"Ok.")),
    ((200, b"Ok."), (200, b'{"added_torrent_ids":["test-hash"],"failure_count":0,"pending_count":0,"success_count":1}')),
])
def test_login_and_upload_support_qbittorrent_success_responses(client, api, tmp_path, login_result, add_result):
    api.login_result, api.add_result = login_result, add_result
    session = client.connect_to_qbittorrent(api.address)
    assert session is not None
    torrent = tmp_path / "example.torrent"
    torrent.write_bytes(b"test-torrent-content")
    save_path = str(tmp_path / "downloads")
    assert client.add_torrents(
        session, api.address, [(str(torrent), "nested", "auto")], save_path, True, "test"
    ) == (1, 0)
    path, cookie, body = api.upload
    assert path == "/api/v2/torrents/add"
    assert cookie == "QBT_SID_9095=test-session"
    for name, value in [("savepath", str(tmp_path / "downloads" / "nested")), ("skip_checking", "true"), ("category", "test")]:
        assert f'name="{name}"\r\n\r\n{value}\r\n'.encode() in body
    assert b"test-torrent-content" in body
    session.close()


def test_http_200_login_failure_is_not_reported_as_success(client, api, capsys):
    api.login_result = (200, b"Fails.")
    assert client.connect_to_qbittorrent(api.address) is None
    assert "身份验证成功" not in capsys.readouterr().out


@pytest.mark.parametrize("result", [
    (200, b"Fails."),
    (200, b'{"success_count":0,"failure_count":1,"pending_count":0}'),
    (200, b"{}"),
    (409, b"Conflict"),
    (202, b'{"success_count":0,"failure_count":0,"pending_count":1}'),
])
def test_unsuccessful_upload_is_counted_as_failure(client, api, tmp_path, result):
    api.login_result = (200, b"Ok.")
    api.add_result = result
    session = client.connect_to_qbittorrent(api.address)
    torrent = tmp_path / "invalid.torrent"
    torrent.write_bytes(b"invalid")
    assert client.add_torrents(
        session, api.address, [(str(torrent), "", "auto")], str(tmp_path), True, "test"
    ) == (0, 1)
    session.close()
