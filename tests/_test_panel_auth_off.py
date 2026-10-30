"""面板密码校验默认关闭（WB_PANEL_AUTH 默认 off）：面板全开，Key 边界不动。

背景：本机自用，不想每次开看板都输密码，业主明确要求「面板一律不校验密码」。
所以默认值翻成 off，`WB_PANEL_AUTH=on` 才是上游那套要密码的行为。这里钉住
的是这个开关的**作用域**：

  · 面板路由（读 + 写 + 复制明文 Key + 改密码）——免密码时匿名可达；
  · /panel/status —— 回报「不需要密码」，看板据此直接进面板；
  · 只读 GET —— 免 Key 放行，看板要拉 /v1/models 这类接口；
  · /v1/chat/completions、/v1/messages —— **仍然要 API Key**，
    那不是密码而是额度边界，面板免密码不该顺手把它也放开。

请求走真实的 do_GET / do_POST（内存 socket），钉的是分发器的行为，不是某个
handler 的内部实现。无网络：模型目录与更新检查都是注入的。

    python tests/_test_panel_auth_off.py
"""
import email
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _isolated_dirs import isolated_data_dirs  # noqa: E402  (its own data root)

_TMP = isolated_data_dirs("wb-panel-auth-off-")

import wb_proxy as proxy  # noqa: E402
import wb_settings  # noqa: E402

KEY = "panel-auth-off-key"
MODEL_ID = "injected-panel-auth-off-model"


OTHER_MODEL_ID = "injected-other-model"


def injected_models(realm=None):
    """The model listing, without walking anything upstream."""
    return [(MODEL_ID, {"name": "Injected"}), (OTHER_MODEL_ID, {"name": "Other"})]


class StubUpdates(object):
    """Stands in for the release checker; the boundary is what is under test."""

    def __init__(self):
        self.last = {"current_version": proxy.running_version(),
                     "latest_version": None, "update_available": False}

    def check(self, manual=False):
        self.last = {"current_version": proxy.running_version(),
                     "latest_version": "9.9.9", "update_available": True}
        return dict(self.last)

    def status(self):
        return dict(self.last)


class DispatchRequest(proxy.Handler):
    """A real Handler driven over an in-memory socket."""

    def __init__(self, path, headers=None, command="GET", body=b""):
        self.path = path
        self.command = command
        self.request_version = "HTTP/1.1"
        self.close_connection = True
        raw_headers = dict(headers or {})
        # 没这个头，_payload_or_error() 会按 0 字节读 body，POST 的 JSON 就成了空字典
        # —— 于是「current password is wrong」之类看不出是测试桩自己的问题。
        if body and not any(k.lower() == "content-length" for k in raw_headers):
            raw_headers["Content-Length"] = str(len(body))
        raw = "".join("%s: %s\r\n" % item for item in raw_headers.items())
        self.headers = email.message_from_string(raw)
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.status = None
        self.sent_headers = {}
        self.client_address = ("127.0.0.1", 0)

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, key, value):
        self.sent_headers[key] = value

    def end_headers(self):
        pass

    def log_message(self, fmt, *args):
        pass

    def dispatch(self):
        getattr(self, "do_" + self.command)()
        raw = self.wfile.getvalue().decode("utf-8")
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = None
        return self.status, payload, raw


class PanelAuthSwitchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="panel-auth-off-")
        self.addCleanup(self._tmp.cleanup)
        self.directory = self._tmp.name
        wb_settings.set_api_keys(self.directory, [
            {"id": "k1", "name": "k", "key": KEY, "enabled": True}])
        self.updates = StubUpdates()

    # ---------------------------------------------------------------- 工具
    def call(self, path, headers=None, command="GET", body=b"", required=False):
        """跑一次真实分发。required 是本次想验证的 WB_PANEL_AUTH 口径。"""
        request = DispatchRequest(path, headers=headers, command=command, body=body)
        self.last = request
        with mock.patch.multiple(
                proxy, ACCOUNTS_DIR=self.directory, API_KEY=None, POOL=None,
                PRICING=None, UPDATES=self.updates, SCHEDULER=None,
                fetch_models=injected_models, PANEL_AUTH_REQUIRED=required):
            return request.dispatch()

    def session(self):
        return {"X-Panel-Token": proxy.PANEL.create()}

    # ------------------------------------------------------------ 1) 解析器
    def test_the_switch_accepts_the_usual_spellings(self):
        for value in ("off", "OFF", "  Off  ", "0", "false", "no", "disabled"):
            with self.subTest(value=value):
                self.assertFalse(proxy.panel_auth_required({"WB_PANEL_AUTH": value}))

    def test_the_switch_is_off_by_default(self):
        # 本机构建的默认口径：不要密码。空值也按「不要密码」处理。
        self.assertFalse(proxy.panel_auth_required({}))
        self.assertFalse(proxy.panel_auth_required({"WB_PANEL_AUTH": ""}))
        self.assertFalse(proxy.panel_auth_required({"WB_PANEL_AUTH": "   "}))
        # 想要回上游行为就显式打开；未知值按「要密码」处理（fail-safe）。
        for value in ("on", "1", "true", "yes", "anything-else"):
            with self.subTest(value=value):
                self.assertTrue(proxy.panel_auth_required({"WB_PANEL_AUTH": value}))

    # ------------------------------------------------- 2) 默认口径没被松动
    def test_the_default_still_refuses_an_anonymous_panel_read(self):
        for path in ("/settings", "/accounts", "/logs", "/proxy/slots"):
            with self.subTest(path=path):
                status, payload, _ = self.call(path, required=True)
                self.assertEqual(status, 401, "%s answered %s" % (path, status))
                self.assertIn("panel password required", payload["error"]["message"])

    def test_the_default_still_refuses_an_anonymous_panel_write(self):
        status, payload, _ = self.call("/updates/check", command="POST", body=b"{}",
                                       required=True)
        self.assertEqual(status, 401)
        self.assertIn("panel password required", payload["error"]["message"])

    # --------------------------------------------- 3) 关掉密码：面板直接进
    def test_status_tells_the_dashboard_not_to_ask(self):
        status, payload, _ = self.call("/panel/status", required=False)
        self.assertEqual(status, 200)
        self.assertIs(payload["panel_password_required"], False)
        self.assertIs(payload["authenticated"], True)

    def test_panel_reads_are_open(self):
        for path in ("/settings", "/accounts", "/logs", "/proxy/slots"):
            with self.subTest(path=path):
                status, payload, raw = self.call(path, required=False)
                self.assertEqual(status, 200, "%s answered %s" % (path, status))
                self.assertNotIn("panel password required", raw)
                if payload is not None:
                    self.assertNotIn("error", payload)

    def test_panel_writes_are_open(self):
        status, payload, _ = self.call("/updates/check", command="POST", body=b"{}",
                                       required=False)
        self.assertEqual(status, 200, "POST /updates/check answered %s" % status)
        self.assertEqual(payload.get("latest_version"), "9.9.9")

    def test_a_keyless_read_only_get_reaches_the_model_list(self):
        # 看板拉模型目录走 /v1/models，它由 _key_ok() 把关；关掉面板密码后
        # 必须免 Key 可用，否则「不用登录」的看板会是个空壳。
        status, payload, _ = self.call("/v1/models", required=False)
        self.assertEqual(status, 200, "GET /v1/models answered %s" % status)
        self.assertIn(MODEL_ID, json.dumps(payload))

    # --------------------------- 4) 免密码后面板全开，但 Key 的边界仍在
    def test_chat_still_requires_the_api_key(self):
        status, payload, _ = self.call("/v1/chat/completions", command="POST",
                                       body=b'{"model": "x", "messages": []}',
                                       required=False)
        self.assertEqual(status, 401, "chat answered %s without a key" % status)
        self.assertIn("invalid api key", payload["error"]["message"])

    def test_the_anthropic_bridge_still_requires_the_api_key(self):
        status, payload, _ = self.call("/v1/messages", command="POST",
                                       body=b'{"model": "x", "messages": []}',
                                       required=False)
        self.assertEqual(status, 401, "messages answered %s without a key" % status)

    def test_revealing_a_stored_key_follows_the_switch(self):
        # 免密码（默认）：匿名就能读到明文 Key —— 业主明确要求面板一律不校验密码。
        status, payload, _ = self.call("/settings/reveal?id=k1", required=False)
        self.assertEqual(status, 200, "reveal answered %s" % status)
        self.assertEqual(payload.get("key"), KEY)
        # 想要回密码校验时，它重新变成 401 —— 证明开关仍然管得住。
        status, payload, _ = self.call("/settings/reveal?id=k1", required=True)
        self.assertEqual(status, 401)
        self.assertIn("panel password required", payload["error"]["message"])

    def test_changing_the_password_follows_the_switch(self):
        status, _, _ = self.call("/panel/password", command="POST",
                                 body=b'{"current": "admin", "new": "newpass"}',
                                 required=False)
        self.assertEqual(status, 200, "panel/password answered %s" % status)
        status, payload, _ = self.call("/panel/password", command="POST",
                                       body=b'{"current": "newpass", "new": "otherpass"}',
                                       required=True)
        self.assertEqual(status, 401)
        self.assertIn("panel password required", payload["error"]["message"])


    # ------------------- 5) 免密码不能把 API Key 的边界一起拆掉（1.9.6 回归）
    def test_a_wrong_key_is_still_refused_on_a_read_only_get(self):
        # 1.9.5 把「匿名 GET 放行」写在 identify_key() 之前，于是带错 Key 的
        # GET /v1/models 也回 200 —— Key 等于形同虚设。
        status, payload, _ = self.call("/v1/models",
                                       {"Authorization": "Bearer wrong-key"},
                                       required=False)
        self.assertEqual(status, 401, "wrong key answered %s" % status)
        self.assertIn("invalid api key", payload["error"]["message"])

    def test_a_valid_key_is_still_identified_on_a_read_only_get(self):
        # 按 Key 过滤模型依赖 self.key_entry；GET 旁路若提前短路，它永远是 None。
        wb_settings.set_api_keys(self.directory, [
            {"id": "k1", "name": "k", "key": KEY, "enabled": True,
             "models": [MODEL_ID]}])
        wb_settings.set_filter_models_by_key(self.directory, True)

        status, payload, _ = self.call("/v1/models", required=False)
        self.assertEqual(status, 200)
        anon_ids = [m["id"] for m in payload.get("data", [])]
        self.assertEqual(sorted(anon_ids), sorted([MODEL_ID, OTHER_MODEL_ID]),
                         "匿名只读应当看到全量目录")

        status, payload, _ = self.call("/v1/models",
                                       {"Authorization": "Bearer " + KEY},
                                       required=False)
        self.assertEqual(status, 200)
        key_ids = [m["id"] for m in payload.get("data", [])]
        self.assertEqual(key_ids, [MODEL_ID],
                         "受限 Key 只应看到它允许的模型，实际 %r" % (key_ids,))

    # ------------------------------- 6) 出站身份版本号：免密时不再要二次密码
    def test_identity_versions_needs_no_password_when_off(self):
        body = json.dumps({"identity_versions": {"cli": "9.9.9"}}).encode()
        status, payload, _ = self.call("/settings/save", command="POST", body=body,
                                       required=False)
        self.assertEqual(status, 200, "settings/save answered %s" % status)
        self.assertEqual(payload.get("identity_versions"), {"cli": "9.9.9"})

    def test_identity_versions_still_needs_the_password_when_gated(self):
        body = json.dumps({"identity_versions": {"cli": "9.9.9"}}).encode()
        status, payload, _ = self.call("/settings/save", command="POST", body=body,
                                       required=True)
        self.assertEqual(status, 401, "settings/save answered %s" % status)

    # ------------------------- 7) 首帧：免密码时页面壳自己就写着「不用登录」
    def test_the_dashboard_shell_declares_the_passwordless_mode(self):
        status, _, raw = self.call("/", required=False)
        self.assertEqual(status, 200, "GET / answered %s" % status)
        self.assertIn('data-panel-auth="off"', raw)
        etag_off = self.last.sent_headers.get("ETag")
        status, _, raw = self.call("/", required=True)
        self.assertIn('data-panel-auth="on"', raw)
        etag_on = self.last.sent_headers.get("ETag")
        self.assertTrue(etag_off and etag_on and etag_off != etag_on,
                        "ETag 必须随密码模式变化（否则 304 会把旧壳发回去）："
                        "%r vs %r" % (etag_off, etag_on))

    # --------------------------------- 8) 免密码后的最低防线：跨站写请求挡掉
    def test_a_cross_site_write_is_refused(self):
        status, payload, _ = self.call(
            "/settings/save", command="POST", body=b"{}",
            headers={"Origin": "https://evil.example", "Host": "127.0.0.1:8788"},
            required=False)
        self.assertEqual(status, 401, "cross-site POST answered %s" % status)
        self.assertIn("panel password required", payload["error"]["message"])

    def test_same_origin_and_script_writes_are_allowed(self):
        status, _, _ = self.call(
            "/settings/save", command="POST", body=b"{}",
            headers={"Origin": "http://127.0.0.1:8788", "Host": "127.0.0.1:8788"},
            required=False)
        self.assertEqual(status, 200, "same-origin POST answered %s" % status)
        # 没有 Origin（curl / Python 脚本 / 单测桩）照常放行
        status, _, _ = self.call("/settings/save", command="POST", body=b"{}",
                                 required=False)
        self.assertEqual(status, 200, "Origin-less POST answered %s" % status)

    def test_a_cross_site_read_is_not_blocked(self):
        # 只挡写：跨站 GET 拿不到响应体（同源策略在浏览器侧），挡它没有收益。
        status, _, _ = self.call("/settings",
                                 headers={"Origin": "https://evil.example",
                                          "Host": "127.0.0.1:8788"},
                                 required=False)
        self.assertEqual(status, 200, "cross-site GET answered %s" % status)


if __name__ == "__main__":
    unittest.main()
