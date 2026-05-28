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
STAGED_FILE = RUNTIME_DIR / "v2rays.next"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

HEADER_LINES = [
    "#profile-title: base64:TXkgdjJyYXkgQ29sbGVjdGlvbg==",
    "#profile-update-interval: 1",
    "#subscription-userinfo: upload=29; download=12; total=10737418240000000; expire=2546249531",
    "#support-url: https://github.com/Abdulhossein/All-in-One/",
    "#profile-web-page-url: https://github.com/Abdulhossein/All-in-One/edit/main/v2ray",
]

# ----------------------------------------------------------------------
# محدودیت‌های گیتهاب
# ----------------------------------------------------------------------
MAX_LINKS_PER_RUN = 3        # تعداد سابسکریپشن‌ها در هر اجرا
MAX_TESTS_PER_RUN = 500      # کاهش تست‌ها برای صرفه‌جویی در منابع
CONNECT_TIMEOUT = 1.5        # ثانیه (کمتر از قبل)
HTTP_TIMEOUT = 15            # ثانیه
TEST_BATCH_SIZE = 20         # تست گروهی برای کاهش sleep
DEFAULT_CURSOR = 0

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

# Session global (با بستن صریح در انتها)
SESSION = create_session_with_retries()

def fetch_content(url: str) -> Optional[str]:
    """دریافت محتوا با ۲ بار تلاش مجدد (fail‑safe)."""
    for attempt in range(3):
        try:
            resp = SESSION.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            if attempt == 2:
                print(f"Failed to fetch {url}: {e}")
                return None
            time.sleep(2 ** attempt)  # backoff
    return None

def decode_possible_base64(text: str) -> List[str]:
    text = text.strip()
    if not text:
        return []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    # اگر خطوط از قبل plain text باشند
    if any(re.match(r"^(vmess|vless|trojan|ss|socks)://", line) for line in lines):
        return lines
    try:
        decoded = base64.b64decode(normalize_b64(text)).decode("utf-8", errors="ignore")
        decoded_lines = [line.strip() for line in decoded.splitlines() if line.strip()]
        if any(re.match(r"^(vmess|vless|trojan|ss|socks)://", line) for line in decoded_lines):
            return decoded_lines
    except Exception:
        pass
    try:
        decoded = base64.urlsafe_b64decode(normalize_b64(text)).decode("utf-8", errors="ignore")
        decoded_lines = [line.strip() for line in decoded.splitlines() if line.strip()]
        if any(re.match(r"^(vmess|vless|trojan|ss|socks)://", line) for line in decoded_lines):
            return decoded_lines
    except Exception:
        pass
    return lines

def extract_sub_links_from_yaml(content: str, base_url: str) -> List[str]:
    pattern = r"(https?://[^\s\"']+sub_\d+\.txt[^\s\"']*)"
    found = re.findall(pattern, content)
    if found:
        return sorted(set(found))
    sub_names = re.findall(r"sub_(\d+)\.txt", content)
    return [urljoin(base_url, f"sub_{n}.txt") for n in sorted(set(sub_names), key=int)]

def parse_server_from_config(config: str) -> Optional[Tuple[str, int]]:
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
    """تست اتصال TCP با مدیریت ایمن سوکت."""
    server = parse_server_from_config(config)
    if not server:
        return True  # اگر سرور شناسایی نشد، آن را زنده فرض کن
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

def load_existing_configs(file_path: Path) -> Tuple[List[str], Set[str]]:
    """بارگذاری کانفیگ‌های موجود با fail‑safe."""
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

def save_configs(header: List[str], configs: Set[str], file_path: Path) -> None:
    """ذخیره‌سازی اتمیک با نوشتن در فایل موقت و سپس جایگزینی."""
    tmp_path = file_path.with_suffix(file_path.suffix + ".tmp")
    try:
        with tmp_path.open("w", encoding="utf-8") as f:
            for line in header:
                f.write(line + "\n")
            for cfg in sorted(configs):
                f.write(cfg + "\n")
        tmp_path.replace(file_path)  # عملیات اتمیک روی اکثر فایل‌سیستم‌ها
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise

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
        return {"cursor": DEFAULT_CURSOR}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"cursor": DEFAULT_CURSOR}

def save_state(state: Dict) -> None:
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

def process_subscription_link(link: str) -> Tuple[Set[str], Dict[str, int]]:
    stats = {"extracted": 0, "tested": 0, "alive": 0}
    collected = set()
    content = fetch_content(link)
    if not content:
        return collected, stats

    is_yaml_index = bool(re.search(r"sub_\d+\.txt", content, re.IGNORECASE))
    if is_yaml_index:
        sub_links = extract_sub_links_from_yaml(content, link)
        for sub_link in sub_links:
            sub_content = fetch_content(sub_link)
            if not sub_content:
                continue
            configs = decode_possible_base64(sub_content)
            stats["extracted"] += len(configs)
            # تست گروهی برای کاهش sleep
            for i in range(0, len(configs), TEST_BATCH_SIZE):
                batch = configs[i:i+TEST_BATCH_SIZE]
                for cfg in batch:
                    stats["tested"] += 1
                    if stats["tested"] > MAX_TESTS_PER_RUN:
                        return collected, stats
                    if test_config_alive(cfg):
                        collected.add(cfg)
                        stats["alive"] += 1
                time.sleep(0.1)  # pause کوتاه بین batch ها
    else:
        configs = decode_possible_base64(content)
        stats["extracted"] += len(configs)
        for i in range(0, len(configs), TEST_BATCH_SIZE):
            batch = configs[i:i+TEST_BATCH_SIZE]
            for cfg in batch:
                stats["tested"] += 1
                if stats["tested"] > MAX_TESTS_PER_RUN:
                    return collected, stats
                if test_config_alive(cfg):
                    collected.add(cfg)
                    stats["alive"] += 1
            time.sleep(0.1)

    return collected, stats

# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------
def main():
    # اطمینان از وجود مسیرها و فایل‌ها
    ensure_runtime()
    ensure_subscriptions_file()

    header, existing_configs = load_existing_configs(FILE_PATH)
    links = load_subscription_links(SUBS_FILE)
    valid_links = [l for l in links if l and not is_self_reference(l)]

    if not valid_links:
        print("No valid subscription links found.")
        return

    state = load_state()
    cursor = state.get("cursor", DEFAULT_CURSOR)
    if cursor >= len(valid_links):
        cursor = 0

    end_index = min(cursor + MAX_LINKS_PER_RUN, len(valid_links))
    current_batch = valid_links[cursor:end_index]

    print(f"Processing batch {cursor} to {end_index-1} (Total links: {len(valid_links)})")

    new_configs = set()
    total_tested = 0
    for link in current_batch:
        print(f"Processing: {link}")
        collected, stats = process_subscription_link(link)
        new_configs.update(collected)
        total_tested += stats["tested"]
        print(f" -> Extracted: {stats['extracted']}, Tested: {stats['tested']}, Alive: {stats['alive']}")

    print(f"Total new alive configs found in this run: {len(new_configs)}")

    # بارگذاری staged قبلی
    staged_configs = set()
    if STAGED_FILE.exists():
        _, staged = load_existing_configs(STAGED_FILE)
        staged_configs.update(staged)
        print(f"Loaded {len(staged_configs)} previously staged configs.")

    merged_configs = staged_configs.union(new_configs)

    if end_index >= len(valid_links):
        # پایان چرخه – فایل اصلی را به‌روز کن
        print("Full cycle complete! Testing existing configs for liveness...")
        alive_existing = set()
        for cfg in existing_configs:
            if test_config_alive(cfg):
                alive_existing.add(cfg)

        final_configs = alive_existing.union(merged_configs)
        print(f"Final merge: {len(final_configs)} alive configs. Writing to main file.")
        save_configs(header, final_configs, FILE_PATH)

        # پاکسازی فایل staged
        if STAGED_FILE.exists():
            STAGED_FILE.unlink()

        state["cursor"] = 0
        save_state(state)
    else:
        # وسط چرخه – ذخیره در staged
        print(f"Cycle in progress. Staging {len(merged_configs)} configs.")
        save_configs(header, merged_configs, STAGED_FILE)
        state["cursor"] = end_index
        save_state(state)

    # بستن session برای آزادسازی منابع
    SESSION.close()

if __name__ == "__main__":
    main()
