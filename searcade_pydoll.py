import asyncio
import os
import re
import logging
import random
import base64
import json
import urllib.request
from pathlib import Path
from datetime import datetime
from urllib.parse import urlencode

from pydoll.browser.chromium import Chrome
from pydoll.browser.options import ChromiumOptions

import ddddocr
from PIL import Image, ImageDraw

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

EMAIL = os.environ["SEARCADE_EMAIL"]
PASSWORD = os.environ["SEARCADE_PASSWORD"]

BASE_URL = "https://searcade.com/en/admin"
LOGIN_URL = "https://searcade.com/en/admin"
USERVERIA_AUTH_URL = "https://userveria.com/authorize/"
REDIRECT_URI = "https://searcade.com/accounts/userveria/login/callback/"

SCREENSHOT_DIR = Path("./screenshots")
SCREENSHOT_DIR.mkdir(exist_ok=True)

WXPUSHER_TOKEN = os.environ.get("WXPUSHER_TOKEN", "")
WXPUSHER_UID = os.environ.get("WXPUSHER_UID", "")

try:
    ocr = ddddocr.DdddOcr(beta=True, show_ad=False)
except Exception as e:
    log.warning(f"ddddocr 初始化失败，验证码识别将不可用: {e}")
    ocr = None


def wxpush(content: str):
    if not WXPUSHER_TOKEN or not WXPUSHER_UID:
        return

    payload = json.dumps({
        "appToken": WXPUSHER_TOKEN,
        "content": content,
        "contentType": 1,
        "uids": [WXPUSHER_UID],
    }).encode()

    try:
        req = urllib.request.Request(
            "https://wxpusher.zjiecode.com/api/send/message",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get("success"):
                log.info("📨 WxPusher 推送成功")
            else:
                log.warning(f"📨 WxPusher 推送失败: {result}")
    except Exception as e:
        log.warning(f"📨 WxPusher 推送异常: {e}")


def get_cdp_value(result, default=None):
    if isinstance(result, dict):
        try:
            if "result" in result:
                r = result["result"]
                if isinstance(r, dict):
                    if "result" in r and isinstance(r["result"], dict):
                        rr = r["result"]
                        if "value" in rr:
                            return rr["value"]
                    if "value" in r:
                        return r["value"]
        except Exception:
            return default
    return result if result is not None else default


def get_email_variants(email: str) -> list[str]:
    if not email:
        return []

    username = email.split("@")[0] if "@" in email else email
    domain = email.split("@")[1] if "@" in email else ""

    variants = [
        email,
        email.replace("@", "at").replace(".", "-"),
        email.replace("@", "_at_").replace(".", "_"),
        email.replace("@", "[at]").replace(".", "[dot]"),
        email.replace("@", " at ").replace(".", " dot "),
        username,
    ]

    if domain:
        variants.append(domain)
        variants.append(domain.replace(".", "-"))

    return sorted(set(v for v in variants if v), key=len, reverse=True)


async def mask_sensitive_inputs(tab):
    variants = get_email_variants(EMAIL)
    variants_json = json.dumps(variants)

    script = r"""
    (function() {
        const selectors = [
            'input[type="email"]',
            'input[name="email"]',
            'input[type="password"]',
            'input[name="password"]',
            'input[type="text"]'
        ];

        for (let sel of selectors) {
            let el = document.querySelector(sel);
            if (!el) continue;

            let rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) continue;
            if (el._masked) continue;

            el._masked = true;

            let overlay = document.createElement('div');
            overlay.style.position = 'fixed';
            overlay.style.left = rect.left + 'px';
            overlay.style.top = rect.top + 'px';
            overlay.style.width = rect.width + 'px';
            overlay.style.height = rect.height + 'px';
            overlay.style.background = '#333333';
            overlay.style.zIndex = '999999';
            overlay.style.pointerEvents = 'none';
            overlay.style.borderRadius = '4px';
            overlay.setAttribute('data-mask', 'sensitive');
            document.body.appendChild(overlay);
        }

        const variants = __VARIANTS__;

        function escapeRegex(s) {
            return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }

        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        const nodes = [];

        while (walker.nextNode()) {
            nodes.push(walker.currentNode);
        }

        let replacedCount = 0;

        nodes.forEach(node => {
            let text = node.textContent || '';
            let changed = false;

            for (let v of variants) {
                if (!v) continue;

                let regex = new RegExp(escapeRegex(v), 'gi');
                if (regex.test(text)) {
                    text = text.replace(regex, '***');
                    changed = true;
                }
            }

            if (changed) {
                node.textContent = text;
                replacedCount++;
            }
        });

        return {
            overlays: document.querySelectorAll('[data-mask="sensitive"]').length,
            replaced: replacedCount
        };
    })()
    """.replace("__VARIANTS__", variants_json)

    try:
        result = await tab.execute_script(script)
        data = get_cdp_value(result, {})
        if isinstance(data, dict):
            log.info(f"🔒 遮罩: {data.get('overlays', 0)} 个输入框, 替换 {data.get('replaced', 0)} 处文本")
        else:
            log.info("🔒 已应用敏感信息遮罩")
    except Exception as e:
        log.warning(f"遮罩叠加失败: {e}", exc_info=True)


async def unmask_sensitive_inputs(tab):
    script = """
    (function() {
        document.querySelectorAll('[data-mask="sensitive"]').forEach(el => el.remove());
        document.querySelectorAll('input').forEach(el => { el._masked = false; });
        return true;
    })()
    """

    try:
        await tab.execute_script(script)
        log.info("🔓 遮罩层已移除")
    except Exception as e:
        log.warning(f"遮罩移除失败: {e}")


async def blur_sensitive_areas(tab, image_path):
    try:
        variants = get_email_variants(EMAIL)
        variants_json = json.dumps(variants)

        script = r"""
        (function() {
            const dpr = window.devicePixelRatio || 1;
            const rects = [];

            const inputSelectors = [
                'input[type="email"]',
                'input[name="email"]',
                'input[type="password"]',
                'input[name="password"]'
            ];

            for (let sel of inputSelectors) {
                let el = document.querySelector(sel);
                if (!el) continue;

                let r = el.getBoundingClientRect();
                if (r.width > 0 && r.height > 0) {
                    rects.push({
                        x: Math.floor(r.x * dpr),
                        y: Math.floor(r.y * dpr),
                        width: Math.ceil(r.width * dpr),
                        height: Math.ceil(r.height * dpr),
                        type: 'input'
                    });
                }
            }

            const variants = __VARIANTS__;
            const all = document.querySelectorAll('body *');

            for (let el of all) {
                if (el.children.length > 0) continue;

                let txt = el.textContent || '';
                if (!txt) continue;

                for (let v of variants) {
                    if (v && txt.toLowerCase().includes(v.toLowerCase())) {
                        let r = el.getBoundingClientRect();
                        if (r.width > 0 && r.height > 0 && r.height < 200) {
                            rects.push({
                                x: Math.floor(r.x * dpr),
                                y: Math.floor(r.y * dpr),
                                width: Math.ceil(r.width * dpr),
                                height: Math.ceil(r.height * dpr),
                                type: 'text'
                            });
                        }
                        break;
                    }
                }
            }

            return { rects: rects, dpr: dpr };
        })()
        """.replace("__VARIANTS__", variants_json)

        result = await tab.execute_script(script)
        data = get_cdp_value(result, {})

        if not isinstance(data, dict):
            log.warning(f"blur_sensitive_areas: 返回格式异常 {type(data)}")
            return

        rects = data.get("rects", [])
        dpr = data.get("dpr", 1)

        log.info(f"DPR={dpr}, 检测到 {len(rects)} 个敏感区域")

        if not rects:
            return

        img = Image.open(image_path)
        img_w, img_h = img.size
        draw = ImageDraw.Draw(img)

        for rect in rects:
            x = int(rect.get("x", 0))
            y = int(rect.get("y", 0))
            w = int(rect.get("width", 0))
            h = int(rect.get("height", 0))
            t = rect.get("type", "")

            if w <= 0 or h <= 0:
                continue

            padding = 4
            box = (
                max(0, x - padding),
                max(0, y - padding),
                min(img_w, x + w + padding),
                min(img_h, y + h + padding),
            )

            draw.rectangle(box, fill=(40, 40, 40))
            log.info(f"  [{t}] 已填充: {box}")

        img.save(image_path)
        log.info(f"🔒 PIL 二次打码完成: {image_path}")

    except Exception as e:
        log.warning(f"blur_sensitive_areas 失败: {e}", exc_info=True)


async def take_screenshot(browser, tab, name):
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(SCREENSHOT_DIR / f"{ts}_{name}.png")

        await mask_sensitive_inputs(tab)
        await asyncio.sleep(0.8)

        await tab.take_screenshot(path=path)
        log.info(f"📸 原始截图已保存: {path}")

        await blur_sensitive_areas(tab, path)

    except Exception as e:
        log.warning(f"截图失败: {e}", exc_info=True)

    finally:
        try:
            await unmask_sensitive_inputs(tab)
        except Exception as e:
            log.warning(f"遮罩清理失败: {e}")


async def get_text(tab):
    try:
        result = await tab.execute_script("""
        (function() {
            return document.body ? document.body.innerText : '';
        })()
        """)
        return str(get_cdp_value(result, ""))
    except Exception:
        return ""


async def get_url(tab):
    try:
        result = await tab.execute_script("""
        (function() {
            return window.location.href;
        })()
        """)
        return str(get_cdp_value(result, ""))
    except Exception:
        return ""


async def human_delay(min_s=0.3, max_s=0.8):
    await asyncio.sleep(random.uniform(min_s, max_s))


async def wait_for_url_contains(tab, keyword, timeout=10):
    for _ in range(timeout * 2):
        url = await get_url(tab)
        if keyword in url:
            return True
        await asyncio.sleep(0.5)
    return False


async def wait_for_element_by_text(tab, text, timeout=10):
    for _ in range(timeout * 2):
        body = await get_text(tab)
        if text in body:
            return True
        await asyncio.sleep(0.5)
    return False


async def wait_for_input(tab, selectors, timeout=20):
    for _ in range(timeout * 2):
        for sel in selectors:
            script = f"""
            (function() {{
                const el = document.querySelector({json.dumps(sel)});
                if (!el) return false;

                const r = el.getBoundingClientRect();
                return r.width > 0 && r.height > 0 && !el.disabled;
            }})()
            """

            result = await tab.execute_script(script)
            val = get_cdp_value(result, False)

            if val:
                return sel

        await asyncio.sleep(0.5)

    return None


async def js_click_button_by_text(tab, *texts):
    for text in texts:
        script = f"""
        (function() {{
            const target = {json.dumps(text)}.toLowerCase();

            const nodes = Array.from(document.querySelectorAll('button, a, [role="button"]'));

            const el = nodes.find(function(node) {{
                const txt = (node.innerText || node.textContent || '').trim().toLowerCase();
                const visible = node.offsetParent !== null;
                const disabled = node.disabled || node.getAttribute('aria-disabled') === 'true';

                return visible && !disabled && txt.includes(target);
            }});

            if (el) {{
                el.click();
                return true;
            }}

            return false;
        }})()
        """

        result = await tab.execute_script(script)
        clicked = bool(get_cdp_value(result, False))

        if clicked:
            log.info(f"JS 点击成功: '{text}'")
            return text

    return None


async def js_fill_input(tab, value, selectors):
    for sel in selectors:
        script = f"""
        (function() {{
            const el = document.querySelector({json.dumps(sel)});
            if (!el) return false;

            el.focus();

            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype,
                'value'
            ).set;

            nativeInputValueSetter.call(el, {json.dumps(value)});

            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
            el.dispatchEvent(new KeyboardEvent('keyup', {{ bubbles: true }}));

            return true;
        }})()
        """

        result = await tab.execute_script(script)
        ok = bool(get_cdp_value(result, False))

        if ok:
            log.info(f"JS 填写 input 成功: selector='{sel}'")
            return True

    return False


async def submit_current_form(tab):
    script = """
    (function() {
        const btn =
            document.querySelector('button[type="submit"]:not([disabled])') ||
            Array.from(document.querySelectorAll('button')).find(b => {
                const visible = b.offsetParent !== null;
                const disabled = b.disabled || b.getAttribute('aria-disabled') === 'true';
                return visible && !disabled;
            });

        if (btn) {
            btn.click();
            return true;
        }

        const form = document.querySelector('form');
        if (form) {
            if (form.requestSubmit) {
                form.requestSubmit();
            } else {
                form.submit();
            }
            return true;
        }

        return false;
    })()
    """

    result = await tab.execute_script(script)
    return bool(get_cdp_value(result, False))


async def manual_cf_click(tab, timeout=15):
    log.info("尝试手动完成 Cloudflare 验证（Shadow DOM 穿透点击）...")

    for i in range(timeout):
        body = await get_text(tab)
        body_l = body.lower()

        if "email" in body_l or "login" in body_l or "password" in body_l:
            log.info("✅ Cloudflare 验证已通过")
            return True

        try:
            shadow_roots = await tab.find_shadow_roots(deep=False)
            cf_shadow = None

            for sr in shadow_roots:
                try:
                    html = await sr.inner_html
                    if "challenges.cloudflare.com" in html:
                        cf_shadow = sr
                        break
                except Exception:
                    pass

            if cf_shadow is None:
                await asyncio.sleep(1)
                continue

            iframe_el = await cf_shadow.query('iframe[src*="challenges.cloudflare.com"]', timeout=3)
            body_el = await iframe_el.find(tag_name="body", timeout=3)
            inner_shadow = await body_el.get_shadow_root(timeout=3)
            checkbox = await inner_shadow.query("span.cb-i", timeout=3)

            await checkbox.click()

            log.info("已点击 Cloudflare checkbox，等待验证...")
            await asyncio.sleep(3)

            body2 = await get_text(tab)
            body2_l = body2.lower()

            if "email" in body2_l or "login" in body2_l or "password" in body2_l:
                log.info("✅ 点击后验证通过")
                return True

        except Exception as e:
            log.info(f"第 {i + 1}s: {e}")

        await asyncio.sleep(1)

    log.error("Cloudflare 验证超时")
    return False


async def ensure_cf_passed(tab, url, timeout=15):
    try:
        async with tab.expect_and_bypass_cloudflare_captcha():
            await tab.go_to(url)
    except Exception:
        await tab.go_to(url)

    for _ in range(timeout):
        body = await get_text(tab)
        body_l = body.lower()

        if "verify you are human" not in body_l and "cloudflare" not in body_l:
            return True

        await asyncio.sleep(1)

    return await manual_cf_click(tab)


async def fill_captcha(tab):
    if not ocr:
        return ""

    for _ in range(3):
        cap_img = None

        try:
            cap_img = await tab.find(id="allow_login_email_captcha", timeout=5)
        except Exception:
            pass

        if not cap_img:
            try:
                cap_img = await tab.find(tag_name="img", alt="captcha", timeout=5)
            except Exception:
                pass

        if cap_img:
            src = cap_img.get_attribute("src")

            if asyncio.iscoroutine(src):
                src = await src

            if src and src.startswith("data:image"):
                b64 = src.split(",", 1)[1]
                img_bytes = base64.b64decode(b64)

                raw = ocr.classification(img_bytes)
                code = re.sub(r"[^0-9]", "", raw)

                log.info(f"识别验证码: {code}")

                await tab.execute_script(f"""
                (function() {{
                    const input =
                        document.querySelector('#captcha_allow_login_email_captcha') ||
                        document.querySelector('input[name="captcha"]') ||
                        document.querySelector('input[placeholder*="captcha"]');

                    if (input) {{
                        input.focus();
                        input.value = {json.dumps(code)};
                        input.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        input.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    }}
                }})()
                """)

                return code

        await asyncio.sleep(1)

    return ""


def _find_chromium() -> str | None:
    candidates = [
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    ]

    for p in candidates:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            log.info(f"找到 Chromium: {p}")
            return p

    import subprocess

    for cmd in ["chromium-browser", "chromium", "google-chrome", "google-chrome-stable"]:
        try:
            result = subprocess.run(
                ["which", cmd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            path = result.stdout.strip()

            if path and os.path.isfile(path):
                log.info(f"找到 Chromium: {path}")
                return path

        except Exception:
            pass

    return None


async def create_browser():
    opts = ChromiumOptions()
    opts.headless = False

    path = _find_chromium()
    if path:
        opts.binary_location = path

    opts.add_argument("--window-size=1280,720")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-features=VizDisplayCompositor")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--exclude-switches=enable-automation")
    opts.add_argument("--disable-infobars")

    opts.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    opts.add_argument("--disable-save-password-bubble")
    opts.add_argument("--disable-password-generation")
    opts.add_argument("--password-store=basic")
    opts.add_argument("--use-mock-keychain")
    opts.add_argument("--force-device-scale-factor=1")

    opts.browser_preferences = {
        "credentials_enable_service": False,
        "credentials_enable_autosign": False,
        "profile": {
            "password_manager_enabled": False,
            "default_content_setting_values": {
                "notifications": 2,
                "geolocation": 2,
            },
        },
        "autofill": {"enabled": False},
        "intl": {"accept_languages": "en-US,en"},
    }

    browser = await Chrome(options=opts).__aenter__()
    tab = await browser.start()

    try:
        await tab.execute_script("""
        Object.defineProperty(navigator, 'webdriver', {
            get: () => false
        });
        """)
    except Exception:
        pass

    return browser, tab


async def login_searcade(browser, tab):
    log.info("开始登录 Searcade...")

    await ensure_cf_passed(tab, LOGIN_URL)
    await asyncio.sleep(2)
    await take_screenshot(browser, tab, "01_login_page")

    url = await get_url(tab)

    if "userveria.com" not in url:
        log.info("当前未在 Userveria，尝试点击 Login / Sign in")

        clicked = await js_click_button_by_text(tab, "Login", "Log in", "Sign in")

        if clicked:
            await asyncio.sleep(2)

        if not await wait_for_url_contains(tab, "userveria.com", timeout=15):
            log.warning("未自动跳转到 userveria，当前 URL: " + await get_url(tab))

            oauth_url = USERVERIA_AUTH_URL + "?" + urlencode({
                "client_id": "8305d2e2-e91f-4deb-8909-f669259bc23f",
                "redirect_uri": REDIRECT_URI,
                "scope": "profile",
                "response_type": "code",
            })

            await tab.go_to(oauth_url)
            await asyncio.sleep(2)

    await ensure_cf_passed(tab, await get_url(tab))
    await asyncio.sleep(1)

    log.info("等待邮箱输入框")

    email_selector = await wait_for_input(tab, [
        'input[name="email"]',
        'input[type="email"]',
        'input[placeholder*="email" i]',
        'input[autocomplete="email"]',
        'form input',
    ], timeout=20)

    if not email_selector:
        await take_screenshot(browser, tab, "email_input_not_found")
        raise Exception("无法找到邮箱输入框")

    log.info(f"填写邮箱: selector={email_selector}")

    ok = await js_fill_input(tab, EMAIL, [email_selector])
    if not ok:
        raise Exception("无法填写邮箱输入框")

    await human_delay(0.5, 1.2)

    log.info("提交邮箱，进入密码步骤")

    matched = await js_click_button_by_text(
        tab,
        "Continue with email",
        "Continue",
        "继续通过电子邮件",
        "继续",
    )

    if not matched:
        ok = await submit_current_form(tab)
        if not ok:
            await take_screenshot(browser, tab, "continue_button_not_found")
            raise Exception("找不到 Continue with email 按钮")

        log.info("已通过 form fallback 提交邮箱")

    log.info("等待密码输入框出现")

    password_selector = await wait_for_input(tab, [
        'input[name="password"]',
        'input[type="password"]',
        'input[autocomplete="current-password"]',
        'input[placeholder*="password" i]',
    ], timeout=25)

    if not password_selector:
        await take_screenshot(browser, tab, "password_input_not_found")
        body = await get_text(tab)
        log.error("密码框未出现，页面文本片段: " + body[:500])
        raise Exception("邮箱提交后未出现密码输入框")

    log.info(f"填写密码: selector={password_selector}")

    ok = await js_fill_input(tab, PASSWORD, [password_selector])
    if not ok:
        raise Exception("无法填写密码输入框")

    await human_delay(0.5, 1.2)

    log.info("提交密码登录")

    matched = await js_click_button_by_text(
        tab,
        "Log in",
        "Login",
        "Sign in",
        "登录",
    )

    if not matched:
        ok = await submit_current_form(tab)
        if not ok:
            await take_screenshot(browser, tab, "login_button_not_found")
            raise Exception("找不到登录提交按钮")

        log.info("已通过 form fallback 提交登录")

    log.info("等待跳回 Searcade admin")

    signed_in = False
    admin_checked = False

    for i in range(60):
        url = await get_url(tab)
        body = await get_text(tab)
        body_l = body.lower()

        if any(x in body_l for x in [
            "invalid password",
            "incorrect password",
            "wrong password",
            "invalid credentials",
            "try again",
        ]):
            await take_screenshot(browser, tab, "login_invalid_credentials")
            raise Exception("账号或密码错误")

        if "searcade.com" in url and "userveria.com" not in url:
            if "/accounts/userveria/login/callback" not in url and not admin_checked and "/en/admin" not in url and i > 2:
                log.info("已回到 Searcade，主动进入 admin 页面确认登录状态")
                await tab.go_to(LOGIN_URL)
                admin_checked = True
                await asyncio.sleep(2)
                continue

            if (
                "/en/admin" in url
                or "your servers" in body_l
                or "servers" in body_l
                or "logout" in body_l
                or "sign out" in body_l
                or "dashboard" in body_l
            ):
                signed_in = True
                log.info("✅ 登录验证成功，当前 URL: " + url)
                break

        await asyncio.sleep(0.5)

    await take_screenshot(browser, tab, "02_logged_in")

    if not signed_in:
        url = await get_url(tab)
        body = await get_text(tab)

        log.error("❌ 登录后未找到成功标识，URL: " + url)
        log.error("页面文本片段: " + body[:800])

        return False

    log.info("✅ 登录成功，进入服务器页面")

    await tab.go_to(LOGIN_URL)
    await asyncio.sleep(3)

    await tab.execute_script("""
    (function() {
        window.scrollBy(0, 500);
    })()
    """)
    await asyncio.sleep(1)

    server_clicked = await tab.execute_script("""
    (function() {
        const links = Array.from(document.querySelectorAll('a[href]'));

        const srv = links.find(a =>
            /\\/servers\\//.test(a.href) ||
            /admin\\/servers/.test(a.href) ||
            (a.innerText || '').toLowerCase().includes('manage')
        );

        if (srv) {
            srv.click();
            return srv.href;
        }

        return null;
    })()
    """)

    clicked_href = get_cdp_value(server_clicked, None)

    if clicked_href:
        log.info(f"点击服务器卡片: {clicked_href}")
        await asyncio.sleep(3)
    else:
        log.warning("未找到服务器链接，停留在 admin 页面")

    await take_screenshot(browser, tab, "03_server_manage")

    body2 = await get_text(tab)

    if "manage" in body2.lower() or "server" in body2.lower():
        log.info("✅ 服务器页面加载成功")
    else:
        log.warning("⚠️ 未找到服务器管理标识，请检查截图 03_server_manage")

    return True


async def main():
    browser, tab = None, None

    try:
        browser, tab = await create_browser()
        success = await login_searcade(browser, tab)

        if success:
            wxpush("✅ Searcade 自动登录成功")
        else:
            wxpush("❌ Searcade 登录失败，请检查截图")

    except Exception as e:
        log.exception(e)

        if browser and tab:
            await take_screenshot(browser, tab, "99_error")

        wxpush(f"❌ Searcade 登录异常: {e}")

    finally:
        if browser:
            await asyncio.sleep(5)
            await browser.__aexit__(None, None, None)

        log.info("任务结束")


if __name__ == "__main__":
    asyncio.run(main())
