import base64
import json
import os
import re
import socket
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

FILE_PATH = "v2rays"
SUBS_FILE = "subscriptions.txt"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

BASE_DIR = "tools/config-update"
RUNTIME_DIR = os.path.join(BASE_DIR, "runtime")
STATE_FILE = os.path.join(RUNTIME_DIR, "update_state.json")
STAGED_FILE = os.path.join(RUNTIME_DIR, "v2rays.next")

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

MIN_CONFIGS_PER_RUN = 1000
MAX_SUB_LINKS_PER_RUN = 60
RUN_INTERVAL_HOURS = 8.5
FORCE_RESET_DAYS = 10
TCP_TIMEOUT = 3.0
MAX_RUNTIME_SECONDS = 2400


def ensure_dirs():
    os.makedirs(RUNTIME_DIR, exist_ok=True)


def now_utc():
    return datetime.now(timezone.utc)


def now_utc_iso():
    return now_utc().isoformat()


def clean_url(url: str) -> str:
    return url.split('#', 1)[0].strip()


def normalize_b64(text: str) -> str:
    text = text.strip().replace('\n', '').replace('\r', '')
    missing_padding = len(text) % 4
    if missing_padding:
        text += '=' * (4 - missing_padding)
    return text


def is_proxy_line(line: str) -> bool:
    return line.strip().startswith(VALID_SCHEMES)


def sanitize_config_lines(lines: List[str]) -> List[str]:
    cleaned = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
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
                return decoder(normalized).decode('utf-8')
            except Exception:
                continue
    return None


def decode_possible_base64(text: str) -> List[str]:
    text = text.strip()
    if not text:
        return []
    direct = sanitize_config_lines(text.splitlines())
    if direct:
        return direct
    decoded = try_b64decode(text)
    if decoded:
        return sanitize_config_lines(decoded.splitlines())
    return []


def atomic_write_text(path: str, text: str) -> None:
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix='.tmp_', dir=directory, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def atomic_write_json(path: str, data: Dict) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2))


def default_state() -> Dict:
    return {
        'cursor': 0,
        'cycle_started_at': now_utc_iso(),
        'last_run_at': None,
        'last_reset_at': now_utc_iso(),
        'cycle_number': 1,
        'source_total': 0,
        'last_processed_count': 0,
        'last_tested_count': 0,
        'updated_this_run': False,
    }


def load_state() -> Dict:
    if not os.path.exists(STATE_FILE):
        state = default_state()
        atomic_write_json(STATE_FILE, state)
        return state
    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            state = json.load(f)
        base = default_state()
        for k, v in base.items():
            state.setdefault(k, v)
        return state
    except Exception:
        state = default_state()
        atomic_write_json(STATE_FILE, state)
        return state


def save_state(state: Dict) -> None:
    atomic_write_json(STATE_FILE, state)


def should_force_reset(state: Dict) -> bool:
    last_reset_at = state.get('last_reset_at')
    if not last_reset_at:
        return True
    try:
        last_dt = datetime.fromisoformat(last_reset_at)
    except Exception:
        return True
    return now_utc() - last_dt >= timedelta(days=FORCE_RESET_DAYS)


def create_session_with_retries(retries: int = 2, backoff_factor: float = 0.4) -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(['HEAD', 'GET', 'OPTIONS']),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_remax=max(retries, 1))
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# fix adapter after defining function

def create_session_with_retries(retries: int = 2, backoff_factor: float = 0.4) -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(['HEAD', 'GET', 'OPTIONS']),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


SESSION = create_session_with_retries()


def fetch_content(url: str) -> Optional[str]:
    try:
        r = SESSION.get(url, timeout=20, headers={'User-Agent': USER_AGENT})
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f'Error fetching {url}: {e}')
        return None


def extract_sub_links_from_yaml(content: str, base_url: str) -> List[str]:
    found = re.findall(SUB_LINK_PATTERN, content)
    if found:
        return sorted(set(found))
    sub_names = re.findall(r'sub_(\d+)\.txt', content)
    return [urljoin(base_url, f'sub_{n}.txt') for n in sorted(set(sub_names), key=int)]


def parse_vmess(config: str) -> Optional[Tuple[str, int]]:
    payload = config[len('vmess://'):]
    decoded = try_b64decode(payload)
    if not decoded:
        return None
    data = json.loads(decoded)
    host = data.get('add')
    port = data.get('port')
    return (host, int(port)) if host and port else None


def parse_vless_trojan_socks(config: str) -> Optional[Tuple[str, int]]:
    parsed = urlparse(config)
    if parsed.hostname and parsed.port:
        return parsed.hostname, parsed.port
    return None


def parse_ss(config: str) -> Optional[Tuple[str, int]]:
    rest = config[len('ss://'):]
    rest = rest.split('#', 1)[0].split('?', 1)[0]
    if '@' in rest:
        host_port = rest.split('@', 1)[1]
        host, port = host_port.rsplit(':', 1)
        return host, int(port)
    decoded = try_b64decode(rest)
    if decoded and '@' in decoded:
        host_port = decoded.split('@', 1)[1].split('#', 1)[0].split('?', 1)[0]
        host, port = host_port.rsplit(':', 1)
        return host, int(port)
    return None


def parse_server_from_config(config: str) -> Optional[Tuple[str, int]]:
    try:
        config = config.strip()
        if config.startswith('vmess://'):
            return parse_vmess(config)
        if config.startswith(('vless://', 'trojan://', 'socks://')):
            return parse_vless_trojan_socks(config)
        if config.startswith('ss://'):
            return parse_ss(config)
    except Exception as e:
        print(f'Parse error: {e}')
    return None


def test_config_alive(config: str, timeout: float = TCP_TIMEOUT) -> bool:
    server = parse_server_from_config(config)
    if not server:
        return False
    host, port = server
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def load_existing_configs(file_path: str) -> Set[str]:
    configs: Set[str] = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if is_proxy_line(line):
                    configs.add(line)
    except FileNotFoundError:
        pass
    return configs


def save_configs(configs: Set[str], file_path: str) -> None:
    content = '\n'.join(HEADER_LINES + sorted(configs)) + '\n'
    atomic_write_text(file_path, content)
    print(f'Saved {len(configs)} configs to {file_path}.')


def load_subscription_links(subs_file: str) -> List[str]:
    links: List[str] = []
    seen: Set[str] = set()
    try:
        with open(subs_file, 'r', encoding='utf-8') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                normalized = clean_url(line)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    links.append(normalized)
    except FileNotFoundError:
        pass
    return links


def build_all_links() -> List[str]:
    all_links: List[str] = []
    seen: Set[str] = set()
    for link in DEFAULT_LINKS + load_subscription_links(SUBS_FILE):
        normalized = clean_url(link)
        if normalized and normalized not in seen:
            seen.add(normalized)
            all_links.append(normalized)
    return all_links


def process_subscription_link(link: str, collected_configs: Set[str], stats: Dict[str, Dict[str, int]]) -> int:
    link = clean_url(link)
    if not link:
        return 0
    print(f'Processing: {link}')
    stats.setdefault(link, {'fetched': 0, 'valid': 0, 'alive': 0})
    content = fetch_content(link)
    if not content:
        return 0
    tested = 0
    if re.search(r'sub_\d+\.txt', content, re.IGNORECASE):
        print('  Detected YAML index. Extracting sub-links...')
        sub_links = extract_sub_links_from_yaml(content, link)
        for sub_link in sub_links:
            sub_content = fetch_content(sub_link)
            if not sub_content:
                continue
            configs = decode_possible_base64(sub_content)
            stats[link]['fetched'] += len(configs)
            for cfg in configs:
                stats[link]['valid'] += 1
                tested += 1
                if test_config_alive(cfg):
                    collected_configs.add(cfg)
                    stats[link]['alive'] += 1
    else:
        configs = decode_possible_base64(content)
        stats[link]['fetched'] += len(configs)
        for cfg in configs:
            stats[link]['valid'] += 1
            tested += 1
            if test_config_alive(cfg):
                collected_configs.add(cfg)
                stats[link]['alive'] += 1
    return tested


def print_stats(stats: Dict[str, Dict[str, int]]) -> None:
    print('\n===== Source Summary =====')
    for link, data in stats.items():
        print(f"{link}\n  Extracted: {data['fetched']}\n  Tested:    {data['valid']}\n  Alive:     {data['alive']}")
    print('==========================\n')


def reset_cycle(state: Dict) -> Dict:
    print('Resetting cycle...')
    if os.path.exists(STAGED_FILE):
        os.remove(STAGED_FILE)
    state['cursor'] = 0
    state['cycle_started_at'] = now_utc_iso()
    state['last_reset_at'] = now_utc_iso()
    state['cycle_number'] = int(state.get('cycle_number', 1)) + 1
    state['updated_this_run'] = False
    return state


def main() -> None:
    ensure_dirs()
    state = load_state()

    if should_force_reset(state):
        state = reset_cycle(state)
        save_state(state)

    all_links = build_all_links()
    state['source_total'] = len(all_links)

    if not all_links:
        print('No subscription links found.')
        state['last_run_at'] = now_utc_iso()
        save_state(state)
        return

    cursor = int(state.get('cursor', 0))
    if cursor >= len(all_links):
        state = reset_cycle(state)
        cursor = 0

    existing_configs = load_existing_configs(FILE_PATH)
    staged_configs = load_existing_configs(STAGED_FILE)
    base_configs = existing_configs | staged_configs

    print(f'Loaded {len(existing_configs)} existing configs from final output.')
    print(f'Loaded {len(staged_configs)} existing configs from staged output.')
    print(f'Total subscription links to process: {len(all_links)}')
    print(f'Starting cursor: {cursor}')

    new_configs: Set[str] = set()
    stats: Dict[str, Dict[str, int]] = {}
    checked_configs = 0
    processed_links = 0
    start = time.perf_counter()

    while cursor < len(all_links):
        if time.perf_counter() - start > MAX_RUNTIME_SECONDS:
            print('Stopping due to runtime guard.')
            break
        link = all_links[cursor]
        tested_now = process_subscription_link(link, new_configs, stats)
        checked_configs += tested_now
        processed_links += 1
        cursor += 1
        if checked_configs >= MIN_CONFIGS_PER_RUN:
            break
        if processed_links >= MAX_SUB_LINKS_PER_RUN:
            break

    merged_configs = base_configs | new_configs
    updated = False
    if merged_configs != base_configs:
        save_configs(merged_configs, STAGED_FILE)
        updated = True

    state['last_processed_count'] = processed_links
    state['last_tested_count'] = checked_configs
    state['updated_this_run'] = updated
    state['last_run_at'] = now_utc_iso()

    if cursor >= len(all_links):
        print('Reached end of subscription links. Promoting staged output to final file.')
        if os.path.exists(STAGED_FILE):
            save_configs(merged_configs, FILE_PATH)
        state = reset_cycle(state)
    else:
        state['cursor'] = cursor

    save_state(state)
    print(f'Processed links this run: {processed_links}')
    print(f'Tested configs this run: {checked_configs}')
    print(f'Found {len(new_configs)} alive configs from current batch.')
    print(f'Merged configs so far: {len(merged_configs)} total.')
    print_stats(stats)


if __name__ == '__main__':
    main()
