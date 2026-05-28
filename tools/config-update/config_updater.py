import base64
import time 
import json
import os
import re
import socket
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent.parent

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

MAX_LINKS_PER_RUN = 2
MAX_TESTS_PER_RUN = 2500
CONNECT_TIMEOUT = 3.0
HTTP_TIMEOUT = 20
DEFAULT_CURSOR = 0


def ensure_runtime():
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)


def clean_url(url: str) -> str:
    return url.split("#", 1)[0].strip()


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
    try:
        resp = SESSION.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None


def decode_possible_base64(text: str) -> List[str]:
    text = text.strip()
    if not text:
        return []

    lines = [line.strip() for line in text.splitlines() if line.strip()]
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
    pattern = r"(https?://[^s"']+sub_d+.txt[^s"']*)"
    found = re.findall(pattern, content)
    if found:
        return sorted(set(found))
    sub_names = re.findall(r"sub_(d+).txt", content)
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

    except Exception as e:
        print(f"  Parse error: {e}")
    return None


def test_config_alive(config: str, timeout: float = CONNECT_TIMEOUT) -> bool:
    server = parse_server_from_config(config)
    if not server:
        return True
    host, port = server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return True
        return False
    except Exception:
        return False


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


def save_configs(header: List[str], configs: Set[str], file_path: Path) -> None:
    with file_path.open("w", encoding="utf-8") as f:
        for line in header:
            f.write(line + "
")
        for cfg in sorted(configs):
            f.write(cfg + "
")
    print(f"Saved {len(configs)} configs to {file_path} (header preserved).")


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

    print(f"Processing: {link}")
    content = fetch_content(link)
    if not content:
        return collected, stats

    is_yaml_index = bool(re.search(r"sub_d+.txt", content, re.IGNORECASE))
    if is_yaml_index:
        sub_links = extract_sub_links_from_yaml(content, link)
        for sub_link in sub_links:
            sub_content = fetch_content(sub_link)
            if not sub_content:
                continue
            configs = decode_possible_base64(sub_content)
            stats["extracted"] += len(configs)
            for cfg in configs:
                stats["tested"] += 1
                if stats["tested"] > MAX_TESTS_PER_RUN:
                    return collected, stats
                if test_config_alive(cfg):
                    collected.add(cfg)
                    stats["alive"] += 1
    else:
        configs = decode_possible_base64(content)
        stats["extracted"] += len(configs)
        for cfg in configs:
            stats["tested"] += 1
            if stats["tested"] > MAX_TESTS_PER_RUN:
                return collected, stats
            if test_config_alive(cfg):
                collected.add(cfg)
                stats["alive"] += 1

    return collected, stats


def main():
    ensure_runtime()

    state = load_state()
    cursor = int(state.get("cursor", DEFAULT_CURSOR))

    header, existing_configs = load_existing_configs(FILE_PATH)
    staged_header, staged_existing_configs = load_existing_configs(FILE_PATH)

    print(f"Loaded {len(existing_configs)} existing configs from final output.")
    print(f"Loaded {len(staged_existing_configs)} existing configs from staged output.")

    default_links = [
        "https://raw.githubusercontent.com/hiddify/hiddify-app/refs/heads/main/test.configs/mahsa#Mahsa",
        "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt#Anonymous",
        "https://raw.githubusercontent.com/hiddify/hiddify-app/refs/heads/main/test.configs/warp#Warp%20&%20Psiphon",
    ]

    additional_links = load_subscription_links(SUBS_FILE)
    all_links = default_links + additional_links

    print(f"Total subscription links to process: {len(all_links)}")
    print(f"Starting cursor: {cursor}")

    if cursor >= len(all_links):
        cursor = 0

    end = min(cursor + MAX_LINKS_PER_RUN, len(all_links))
    batch_links = all_links[cursor:end]

    new_configs = set()
    processed = 0
    total_tested = 0
    summary = []

    for link in batch_links:
        collected, stats = process_subscription_link(link)
        processed += 1
        total_tested += stats["tested"]
        new_configs.update(collected)
        summary.append((link, stats))
        print(f"Processed links this run: {processed}")
        print(f"Tested configs this run: {total_tested}")
        print(f"Found {len(new_configs)} alive configs from current batch.")

    merged_configs = staged_existing_configs.union(new_configs)

    print(f"Merged configs so far: {len(merged_configs)} total.")

    save_configs(header, merged_configs, STAGED_FILE)

    next_cursor = end if end < len(all_links) else 0
    save_state(
        {
            "cursor": next_cursor,
            "total_links": len(all_links),
            "processed_this_run": processed,
            "tested_this_run": total_tested,
            "alive_this_run": len(new_configs),
            "updated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        }
    )

    save_configs(header, merged_configs, FILE_PATH)

    print("
===== Source Summary =====")
    for link, stats in summary:
        print(link)
        print(f"  Extracted: {stats['extracted']}")
        print(f"  Tested:    {stats['tested']}")
        print(f"  Alive:     {stats['alive']}")
    print("==========================")

if __name__ == "__main__":
    main()
