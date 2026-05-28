import base64
import json
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ----------------------------------------------------------------------
# مسیرها و ثابت‌ها (FAIL‑SAFE)
# ----------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent.parent

# فایل خروجی اصلی – همیشه در root ریپو ایجاد می‌شود
FILE_PATH = REPO_ROOT / "v2rays"

SUBS_FILE = REPO_ROOT / "subscriptions.txt"
RUNTIME_DIR = BASE_DIR / "runtime"
STATE_FILE = RUNTIME_DIR / "update_state.json"
RAW_CONFIGS_FILE = RUNTIME_DIR / "raw_configs.txt"
TMP_FINAL_FILE = RUNTIME_DIR / "v2rays.next"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

HEADER_LINES = [
    "#profile-title: base64:TXkgdjJyYXkgQ29sbGVjdGlvbg==",
    "#profile-update-interval: 1",
    "#subscription-userinfo: upload=29; download=12; total=10737418240000000; expire=2546249531",
    "#support-url: https://github.com/Abdulhossein/All-in-One/",
    "#profile-web-page-url: https://github.com/Abdulhossein/All-in-One/edit/main/v2ray",
]

# ----------------------------------------------------------------------
# محدودیت‌های زمانی و منابع
# ----------------------------------------------------------------------
MAX_ALIVE_PER_RUN = 1000      # سقف کانفیگ زندهٔ جدید در هر اجرا
MAX_TESTS_PER_RUN = 2500      # حداکثر تست اتصال در هر اجرا
MAX_TIME_SECONDS = 3300        # ۵۵ دقیقه (زیر ۱ ساعت)
CONNECT_TIMEOUT = 1.5
HTTP_TIMEOUT = 15
TEST_BATCH_SIZE = 25
BATCH_SLEEP = 0.1

# ----------------------------------------------------------------------
# توابع کمکی
# ----------------------------------------------------------------------
def ensure_runtime():
    """ایجاد پوشه‌های ضروری در صورت عدم وجود (fail‑safe)."""
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

def ensure_subscriptions_file():
    """اگر subscriptions.txt وجود نداشت، یک فایل خالی ایجاد کن."""
    if not SUBS_FILE.exists():
        SUBS_FILE.touch()

def clean_url(url: str) -> str:
    return url.split("#", 1)[0].strip()

def is_self_reference(url: str) -> bool:
    return "Abdulhossein/All-in-One" in url and "v2rays" in url

def normalize_b64(text: str) -> str:
    text = text.strip()
    pad = (-len(text)) % 4
    if pad:
        text += "=" * pad
    return text

def create_session_with_retries(retries=3, backoff_factor=0.5):
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

SESSION = create_session_with_retries()

def fetch_content(url: str) -> Optional[str]:
    """دریافت محتوا با ۳ بار تلاش مجدد."""
    for attempt in range(3):
        try:
            resp = SESSION.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            if attempt == 2:
                print(f"Failed to fetch {url}: {e}")
                return None
            time.sleep(2 ** attempt)
    return None

# ----------------------------------------------------------------------
# اعتبارسنجی کانفیگ (رفع مشکل کانفیگ‌های الکی)
# ----------------------------------------------------------------------
PROTOCOL_PATTERN = re.compile(r"^(vmess|vless|trojan|ss|socks)://")

def validate_config(config: str) -> bool:
    """
    بررسی می‌کند که آیا رشتهٔ ورودی یک کانفیگ با فرمت حداقلی معتبر است.
    این تابع برای حذف زباله‌ها پیش از ذخیره‌سازی استفاده می‌شود.
    """
    if not config or not PROTOCOL_PATTERN.match(config):
        return False
    # برای vmess:// باید JSON قابل قبولی داخل آن باشد
    if config.startswith("vmess://"):
        try:
            encoded = config[8:]
            decoded = base64.b64decode(normalize_b64(encoded)).decode("utf-8", errors="ignore")
            data = json.loads(decoded)
            return "add" in data and "port" in data
        except Exception:
            return False
    # برای سایر پروتکل‌ها، همین که با پروتکل درست شروع شوند کافی است
    return True

def decode_possible_base64(text: str) -> List[str]:
    """دیکود محتوا و برگرداندن فقط رشته‌هایی که شبیه کانفیگ معتبر هستند."""
    text = text.strip()
    if not text:
        return []
    lines = [line.strip() for line in text.splitlines() if line.strip()]

    # اگر خطوط از قبل plain text با پروتکل درست باشند
    valid_lines = [l for l in lines if PROTOCOL_PATTERN.match(l)]
    if valid_lines:
        return valid_lines

    candidates = []
    # تلاش برای دیکود base64
    for b64func in [base64.b64decode, base64.urlsafe_b64decode]:
        try:
            decoded = b64func(normalize_b64(text)).decode("utf-8", errors="ignore")
            decoded_lines = [line.strip() for line in decoded.splitlines() if line.strip()]
            valid = [l for l in decoded_lines if PROTOCOL_PATTERN.match(l)]
            if valid:
                return valid
        except Exception:
            continue
    return []

def extract_sub_links_from_yaml(content: str, base_url: str) -> List[str]:
    pattern = r"(https?://[^\s\"']+sub_\d+\.txt[^\s\"']*)"
    found = re.findall(pattern, content)
    if found:
        return sorted(set(found))
    sub_names = re.findall(r"sub_(\d+)\.txt", content)
    return [urljoin(base_url, f"sub_{n}.txt") for n in sorted(set(sub_names), key=int)]

def parse_server_from_config(config: str) -> Optional[Tuple[str, int]]:
    """استخراج host و port از کانفیگ. اگر ناموفق بود None برمی‌گرداند."""
    try:
        if config.startswith("vmess://"):
            encoded = config[8:]
            decoded = base64.b64decode(normalize_b64(encoded)).decode("utf-8", errors="ignore")
            data = json.loads(decoded)
            host = data.get("add")
            port = data.get("port")
            if host and port:
                return host, int(port)
        elif config.startswith("vless://") or config.startswith("trojan://"):
            parsed = urlparse(config)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
        elif config.startswith("ss://"):
            rest = config[5:]
            if "#" in rest:
                rest = rest.split("#", 1)[0]
            if "?" in rest:
                rest = rest.split("?", 1)[0]
            if "@" in rest:
                host_port = rest.split("@", 1)[1]
                if ":" in host_port:
                    host, port = host_port.rsplit(":", 1)
                    return host, int(port)
            else:
                decoded_raw = base64.b64decode(normalize_b64(rest)).decode("utf-8", errors="ignore")
                if "@" in decoded_raw:
                    host_port = decoded_raw.split("@", 1)[1]
                    if ":" in host_port:
                        host, port = host_port.rsplit(":", 1)
                        return host, int(port)
        elif config.startswith("socks://"):
            parsed = urlparse(config)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
    except Exception:
        pass
    return None

def test_config_alive(config: str, timeout: float = CONNECT_TIMEOUT) -> bool:
    """
    تست زنده بودن یک کانفیگ.
    اگر نتوان سرور را استخراج کرد، قطعاً زنده نیست (False برمی‌گردانیم
    تا کانفیگ‌های نامعتبر وارد فایل نهایی نشوند).
    """
    server = parse_server_from_config(config)
    if not server:
        # اصلاح کلیدی: کانفیگی که سرور ندارد را زنده فرض نکنیم
        return False
    host, port = server
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        return result == 0
    except Exception:
        return False
    finally:
        if sock:
            sock.close()

def load_subscription_links(subs_file: Path) -> List[str]:
    links = []
    try:
        with subs_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    links.append(clean_url(line))
    except FileNotFoundError:
        pass
    return links

def load_state() -> Dict:
    if not STATE_FILE.exists():
        return {"phase": "fetch", "current_index": 0, "new_cycle": True}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"phase": "fetch", "current_index": 0, "new_cycle": True}

def save_state(state: Dict) -> None:
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

# ----------------------------------------------------------------------
# فچ تمام کانفیگ‌های خام (با فیلتر اولیه)
# ----------------------------------------------------------------------
def fetch_all_raw_configs(subs_file: Path) -> List[str]:
    """دانلود تمام لینک‌ها، دیکود، اعتبارسنجی و برگرداندن لیست یکتای کانفیگ‌های معتبر."""
    links = load_subscription_links(subs_file)
    valid_links = [l for l in links if l and not is_self_reference(l)]
    if not valid_links:
        print("No valid subscription links.")
        return []

    raw_set = set()
    for link in valid_links:
        print(f"Fetching subscription: {link}")
        content = fetch_content(link)
        if not content:
            continue
        if re.search(r"sub_\d+\.txt", content, re.IGNORECASE):
            sub_links = extract_sub_links_from_yaml(content, link)
            for sub_link in sub_links:
                sub_content = fetch_content(sub_link)
                if not sub_content:
                    continue
                configs = decode_possible_base64(sub_content)
                # اعمال فیلتر validate_config برای حذف زباله‌ها
                filtered = [c for c in configs if validate_config(c)]
                raw_set.update(filtered)
        else:
            configs = decode_possible_base64(content)
            filtered = [c for c in configs if validate_config(c)]
            raw_set.update(filtered)
    return list(raw_set)

def write_raw_configs(raw_configs: List[str]) -> None:
    with RAW_CONFIGS_FILE.open("w", encoding="utf-8") as f:
        for cfg in raw_configs:
            f.write(cfg + "\n")

def load_raw_configs() -> List[str]:
    if not RAW_CONFIGS_FILE.exists():
        return []
    with RAW_CONFIGS_FILE.open("r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

# ----------------------------------------------------------------------
# پردازش یک دسته از کانفیگ‌ها
# ----------------------------------------------------------------------
def process_batch(raw_configs: List[str],
                  start_index: int,
                  max_tests: int,
                  max_alive: int,
                  time_limit: float) -> Tuple[Set[str], int, bool]:
    """برمی‌گرداند: (مجموعه کانفیگ‌های زندهٔ جدید, اندیس بعدی, آیا به انتها رسیده؟)"""
    alive = set()
    tested = 0
    idx = start_index
    start_time = time.monotonic()
    total = len(raw_configs)

    while idx < total:
        elapsed = time.monotonic() - start_time
        if elapsed > time_limit - 60:
            print("Time limit approaching, stopping.")
            break
        if tested >= max_tests:
            print("Test limit reached.")
            break
        if len(alive) >= max_alive:
            print("Alive limit reached.")
            break

        batch_end = min(idx + TEST_BATCH_SIZE, total)
        batch = raw_configs[idx:batch_end]
        for cfg in batch:
            tested += 1
            if tested > max_tests or len(alive) >= max_alive:
                break
            # test_config_alive حالا دیگر کانفیگ نامعتبر را False می‌دهد
            if test_config_alive(cfg):
                alive.add(cfg)
        idx = batch_end
        time.sleep(BATCH_SLEEP)

    completed = (idx >= total)
    return alive, idx, completed

# ----------------------------------------------------------------------
# مدیریت فایل نهایی
# ----------------------------------------------------------------------
def load_existing_configs(file_path: Path) -> Tuple[List[str], Set[str]]:
    header = []
    configs = set()
    try:
        with file_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                header.append(stripped)
            elif stripped:
                configs.add(stripped)
        if not header:
            header = HEADER_LINES.copy()
    except FileNotFoundError:
        header = HEADER_LINES.copy()
    return header, configs

def save_configs_atomic(header: List[str], configs: Set[str], file_path: Path) -> None:
    """ذخیره‌سازی اتمیک با فایل موقت سپس جایگزینی."""
    tmp_path = file_path.with_suffix(file_path.suffix + ".tmp")
    try:
        with tmp_path.open("w", encoding="utf-8") as f:
            for line in header:
                f.write(line + "\n")
            for cfg in sorted(configs):
                f.write(cfg + "\n")
        tmp_path.replace(file_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise

# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------
def main():
    ensure_runtime()
    ensure_subscriptions_file()

    state = load_state()
    phase = state.get("phase", "fetch")
    new_cycle = state.get("new_cycle", True)

    # -------------------------------------------
    # فاز FETCH: دانلود تمام کانفیگ‌های خام
    # -------------------------------------------
    if phase == "fetch":
        print("=== Starting new fetch cycle ===")
        raw_configs = fetch_all_raw_configs(SUBS_FILE)
        if not raw_configs:
            print("No configs fetched. Skipping cycle.")
            SESSION.close()
            return

        write_raw_configs(raw_configs)
        print(f"Fetched {len(raw_configs)} valid raw configs (junk filtered).")

        state["phase"] = "process"
        state["current_index"] = 0
        state["new_cycle"] = True
        save_state(state)

        phase = "process"
        new_cycle = True

    # -------------------------------------------
    # فاز PROCESS: تست کانفیگ‌ها
    # -------------------------------------------
    raw_configs = load_raw_configs()
    if not raw_configs:
        print("Raw configs file missing. Switching to fetch.")
        state["phase"] = "fetch"
        state["new_cycle"] = True
        save_state(state)
        SESSION.close()
        return

    start_index = state.get("current_index", 0)
    time_limit = MAX_TIME_SECONDS

    alive_new, next_index, completed = process_batch(
        raw_configs, start_index, MAX_TESTS_PER_RUN, MAX_ALIVE_PER_RUN, time_limit
    )

    print(f"Batch: tested up to index {next_index}, found {len(alive_new)} alive, completed={completed}")

    state["current_index"] = next_index
    if completed:
        state["phase"] = "fetch"
        state["new_cycle"] = True
        if RAW_CONFIGS_FILE.exists():
            RAW_CONFIGS_FILE.unlink()
    else:
        state["phase"] = "process"
        state["new_cycle"] = False

    save_state(state)

    # مدیریت فایل نهایی
    if new_cycle:
        print("New cycle: rebuilding final file with fresh configs.")
        final_configs = alive_new
    else:
        _, existing_configs = load_existing_configs(FILE_PATH)
        print(f"Merging {len(alive_new)} new into existing {len(existing_configs)}.")
        final_configs = existing_configs.union(alive_new)

    header, _ = load_existing_configs(FILE_PATH)
    if not header:
        header = HEADER_LINES.copy()
    save_configs_atomic(header, final_configs, FILE_PATH)
    print(f"Final file written with {len(final_configs)} configs.")

    SESSION.close()

if __name__ == "__main__":
    main()
