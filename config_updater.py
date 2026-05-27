import base64
import json
import re
import socket
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================
# Configuration
# =========================
FILE_PATH = "v2rays"
SUBS_FILE = "subscriptions.txt"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# این هدر باید همیشه دقیقاً ابتدای فایل خروجی بماند
HEADER_LINES = [
    "#profile-title: base64:TXkgdjJyYXkgQ29sbGVjdGlvbg==",
    "#profile-update-interval: 1",
    "#subscription-userinfo: upload=29; download=12; total=10737418240000000; expire=2546249531",
    "#support-url: https://github.com/Abdulhossein/All-in-One/",
    "#profile-web-page-url: https://github.com/Abdulhossein/All-in-One/edit/main/v2ray"
]

DEFAULT_LINKS = [
    "https://raw.githubusercontent.com/hiddify/hiddify-app/refs/heads/main/test.configs/mahsa#Mahsa",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt#Anonymous",
    "https://raw.githubusercontent.com/hiddify/hiddify-app/refs/heads/main/test.configs/warp#Warp%20&%20Psiphon"
]

VALID_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "socks://")
SUB_LINK_PATTERN = r'(https?://[^\s"\']+sub_\d+\.txt[^\s"\']*)'


# =========================
# Helpers
# =========================
def clean_url(url: str) -> str:
    return url.split("#", 1)[0].strip()


def normalize_b64(text: str) -> str:
    text = text.strip().replace("\n", "").replace("\r", "")
    missing_padding = len(text) % 4
    if missing_padding:
        text += "=" * (4 - missing_padding)
    return text


def is_proxy_line(line: str) -> bool:
    line = line.strip()
    return line.startswith(VALID_SCHEMES)


def sanitize_config_lines(lines: List[str]) -> List[str]:
    cleaned: List[str] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if is_proxy_line(line):
            cleaned.append(line)
    return cleaned


def try_b64decode(text: str) -> Optional[str]:
    text = text.strip()
    if not text:
        return None

    candidates = [text]
    try:
        unquoted = unquote(text)
        if unquoted != text:
            candidates.append(unquoted)
    except Exception:
        pass

    for candidate in candidates:
        normalized = normalize_b64(candidate)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(normalized)
                return decoded.decode("utf-8")
            except Exception:
                continue
    return None


def decode_possible_base64(text: str) -> List[str]:
    text = text.strip()
    if not text:
        return []

    direct_lines = sanitize_config_lines(text.splitlines())
    if direct_lines:
        return direct_lines

    decoded = try_b64decode(text)
    if decoded:
        return sanitize_config_lines(decoded.splitlines())

    return []


def create_session_with_retries(
    retries: int = 3,
    backoff_factor: float = 0.5,
) -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["HEAD", "GET", "OPTIONS"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


SESSION = create_session_with_retries()


def fetch_content(url: str) -> Optional[str]:
    try:
        response = SESSION.get(
            url,
            timeout=20,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None


def extract_sub_links_from_yaml(content: str, base_url: str) -> List[str]:
    found = re.findall(SUB_LINK_PATTERN, content)
    if found:
        return sorted(set(found))

    sub_names = re.findall(r"sub_(\d+)\.txt", content)
    return [urljoin(base_url, f"sub_{n}.txt") for n in sorted(set(sub_names), key=int)]


# =========================
# Config parsing
# =========================
def parse_vmess(config: str) -> Optional[Tuple[str, int]]:
    payload = config[len("vmess://"):]
    decoded = try_b64decode(payload)
    if not decoded:
        return None

    data = json.loads(decoded)
    host = data.get("add")
    port = data.get("port")
    if host and port:
        return host, int(port)
    return None


def parse_vless_trojan_socks(config: str) -> Optional[Tuple[str, int]]:
    parsed = urlparse(config)
    if parsed.hostname and parsed.port:
        return parsed.hostname, parsed.port
    return None


def parse_ss(config: str) -> Optional[Tuple[str, int]]:
    rest = config[len("ss://"):]

    if "#" in rest:
        rest = rest.split("#", 1)[0]
    if "?" in rest:
        rest = rest.split("?", 1)[0]

    if "@" in rest:
        host_port = rest.split("@", 1)[1]
        host, port = host_port.rsplit(":", 1)
        return host, int(port)

    decoded = try_b64decode(rest)
    if decoded and "@" in decoded:
        host_port = decoded.split("@", 1)[1]
        if "#" in host_port:
            host_port = host_port.split("#", 1)[0]
        if "?" in host_port:
            host_port = host_port.split("?", 1)[0]
        host, port = host_port.rsplit(":", 1)
        return host, int(port)

    return None


def parse_server_from_config(config: str) -> Optional[Tuple[str, int]]:
    try:
        config = config.strip()

        if config.startswith("vmess://"):
            return parse_vmess(config)

        if config.startswith(("vless://", "trojan://", "socks://")):
            return parse_vless_trojan_socks(config)

        if config.startswith("ss://"):
            return parse_ss(config)

    except Exception as e:
        print(f"Parse error: {e}")

    return None


# =========================
# Liveness check
# =========================
def test_config_alive(config: str, timeout: float = 3.0) -> bool:
    server = parse_server_from_config(config)
    if not server:
        print("  ? Unparseable config, skipped")
        return False

    host, port = server
    try:
        with socket.create_connection((host, port), timeout=timeout):
            print(f"  ✓ Alive: {host}:{port}")
            return True
    except Exception:
        print(f"  ✗ Dead: {host}:{port}")
        return False


# =========================
# File handling
# =========================
def load_existing_configs(file_path: str) -> Set[str]:
    configs: Set[str] = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if is_proxy_line(line):
                    configs.add(line)
    except FileNotFoundError:
        pass
    return configs


def save_configs(configs: Set[str], file_path: str) -> None:
    with open(file_path, "w", encoding="utf-8") as f:
        for header_line in HEADER_LINES:
            f.write(header_line + "\n")
        for cfg in sorted(configs):
            f.write(cfg + "\n")
    print(f"Saved {len(configs)} configs to {file_path} with fixed header.")


def load_subscription_links(subs_file: str) -> List[str]:
    links: List[str] = []
    seen: Set[str] = set()

    try:
        with open(subs_file, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                normalized = clean_url(line)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    links.append(normalized)
    except FileNotFoundError:
        pass

    return links


# =========================
# Subscription processing
# =========================
def process_subscription_content(content: str) -> List[str]:
    return decode_possible_base64(content)


def process_subscription_link(
    link: str,
    collected_configs: Set[str],
    stats: Dict[str, Dict[str, int]],
) -> None:
    link = clean_url(link)
    if not link:
        return

    print(f"Processing: {link}")
    stats.setdefault(link, {"fetched": 0, "valid": 0, "alive": 0})

    content = fetch_content(link)
    if not content:
        return

    if re.search(r"sub_\d+\.txt", content, re.IGNORECASE):
        print("  Detected YAML index. Extracting sub-links...")
        sub_links = extract_sub_links_from_yaml(content, link)

        for sub_link in sub_links:
            sub_content = fetch_content(sub_link)
            if not sub_content:
                continue

            configs = process_subscription_content(sub_content)
            stats[link]["fetched"] += len(configs)

            for cfg in configs:
                stats[link]["valid"] += 1
                if test_config_alive(cfg):
                    collected_configs.add(cfg)
                    stats[link]["alive"] += 1
    else:
        configs = process_subscription_content(content)
        stats[link]["fetched"] += len(configs)

        for cfg in configs:
            stats[link]["valid"] += 1
            if test_config_alive(cfg):
                collected_configs.add(cfg)
                stats[link]["alive"] += 1


def print_stats(stats: Dict[str, Dict[str, int]]) -> None:
    print("\n===== Source Summary =====")
    for link, data in stats.items():
        print(
            f"{link}\n"
            f"  Extracted: {data['fetched']}\n"
            f"  Tested:    {data['valid']}\n"
            f"  Alive:     {data['alive']}"
        )
    print("==========================\n")


# =========================
# Main
# =========================
def main() -> None:
    existing_configs = load_existing_configs(FILE_PATH)
    print(f"Loaded {len(existing_configs)} existing configs.")

    additional_links = load_subscription_links(SUBS_FILE)

    all_links: List[str] = []
    seen_links: Set[str] = set()

    for link in DEFAULT_LINKS + additional_links:
        normalized = clean_url(link)
        if normalized and normalized not in seen_links:
            seen_links.add(normalized)
            all_links.append(normalized)

    print(f"Total subscription links to process: {len(all_links)}")

    new_configs: Set[str] = set()
    stats: Dict[str, Dict[str, int]] = {}

    for link in all_links:
        process_subscription_link(link, new_configs, stats)

    print(f"Found {len(new_configs)} alive configs from subscriptions.")

    print("Testing existing configs for liveness...")
    alive_existing: Set[str] = set()
    for cfg in existing_configs:
        if test_config_alive(cfg):
            alive_existing.add(cfg)

    print(
        f"Alive existing configs: {len(alive_existing)} "
        f"(removed {len(existing_configs) - len(alive_existing)} dead/unparseable)."
    )

    merged_configs = alive_existing | new_configs
    print(f"Merged configs: {len(merged_configs)} total.")

    save_configs(merged_configs, FILE_PATH)
    print_stats(stats)


if __name__ == "__main__":
    main()
