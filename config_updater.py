import requests
import base64
import re
import socket
from urllib.parse import urljoin, urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import List, Set, Optional, Tuple

# ----- Configuration -----
FILE_PATH = "v2rays"               # main file in your repo
SUBS_FILE = "subscriptions.txt"    # optional extra links
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ----- Header that must stay at the top of the file -----
HEADER_LINES = [
    "#profile-title: base64:TXkgdjJyYXkgQ29sbGVjdGlvbg==",
    "#profile-update-interval: 1",
    "#subscription-userinfo: upload=29; download=12; total=10737418240000000; expire=2546249531",
    "#support-url: https://github.com/Abdulhossein/All-in-One/",
    "#profile-web-page-url: https://github.com/Abdulhossein/All-in-One/edit/main/v2ray"
]
# ---------------------------------------------------------

def clean_url(url: str) -> str:
    """Remove fragment (#...) and extra spaces."""
    return url.split('#')[0].strip()

def create_session_with_retries(retries=3, backoff_factor=0.5):
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def fetch_content(url: str) -> Optional[str]:
    session = create_session_with_retries()
    headers = {'User-Agent': USER_AGENT}
    try:
        resp = session.get(url, timeout=20, headers=headers)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def decode_possible_base64(text: str) -> List[str]:
    text = text.strip()
    if re.search(r'^(vmess|vless|trojan|ss|socks)://', text, re.MULTILINE):
        return [line for line in text.splitlines() if line.strip()]
    try:
        decoded = base64.b64decode(text).decode('utf-8')
        if re.search(r'^(vmess|vless|trojan|ss|socks)://', decoded, re.MULTILINE):
            return [line for line in decoded.splitlines() if line.strip()]
        else:
            return [line for line in text.splitlines() if line.strip()]
    except Exception:
        return [line for line in text.splitlines() if line.strip()]

def extract_sub_links_from_yaml(content: str, base_url: str) -> List[str]:
    pattern = r'(https?://[^\s"\']+sub_\d+\.txt[^\s"\']*)'
    found = re.findall(pattern, content)
    if not found:
        sub_names = re.findall(r'sub_(\d+)\.txt', content)
        found = [urljoin(base_url, f'sub_{n}.txt') for n in set(sub_names)]
    return found

# ---------- Config parsing and testing ----------
def parse_server_from_config(config: str) -> Optional[Tuple[str, int]]:
    """
    Extract IP/host and port from vmess://, vless://, trojan://, ss:// links.
    Returns (host, port) or None if parsing fails.
    """
    try:
        if config.startswith("vmess://"):
            import json
            encoded = config[8:]  # remove 'vmess://'
            decoded = base64.b64decode(encoded).decode('utf-8')
            data = json.loads(decoded)
            host = data.get("add")
            port = data.get("port")
            if host and port:
                return (host, int(port))
        elif config.startswith("vless://") or config.startswith("trojan://"):
            # Format: protocol://uuid@host:port?params#tag
            parsed = urlparse(config)
            host = parsed.hostname
            port = parsed.port
            if host and port:
                return (host, port)
        elif config.startswith("ss://"):
            # Format: ss://base64-encoded#tag or ss://method:password@host:port
            # Try to parse with urlparse after removing 'ss://'
            rest = config[5:]
            if '@' in rest:
                # ss://method:password@host:port
                host_port = rest.split('@')[1]
                host, port = host_port.split(':')
                return (host, int(port))
            else:
                # base64 encoded
                decoded = base64.b64decode(rest).decode('utf-8')
                # decoded format: method:password@host:port
                if '@' in decoded:
                    host_port = decoded.split('@')[1]
                    host, port = host_port.split(':')
                    return (host, int(port))
        elif config.startswith("socks://"):
            parsed = urlparse(config)
            host = parsed.hostname
            port = parsed.port
            if host and port:
                return (host, port)
    except Exception as e:
        print(f"  Parse error for config: {e}")
    return None

def test_config_alive(config: str, timeout: float = 3.0) -> bool:
    """
    Test if the server is alive by attempting a TCP connection.
    Returns True if connection succeeds, False otherwise.
    """
    server = parse_server_from_config(config)
    if not server:
        # If we can't parse, assume it's alive (better to keep it)
        print(f"  Could not parse server from config, keeping it.")
        return True
    host, port = server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            print(f"  ✓ Alive: {host}:{port}")
            return True
        else:
            print(f"  ✗ Dead: {host}:{port}")
            return False
    except Exception as e:
        print(f"  Test error for {host}:{port} -> {e}")
        return False  # consider dead if error

# ---------- File handling with header preservation ----------
def load_existing_configs(file_path: str) -> Tuple[List[str], Set[str]]:
    """
    Reads the file, separates header lines (starting with '#')
    from config lines (everything else). Returns (header_lines, config_set).
    """
    header = []
    configs = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                header.append(stripped)
            elif stripped:
                configs.add(stripped)
        # If header is empty or different, use the default header
        if not header or any(not l.startswith('#profile') for l in header):
            header = HEADER_LINES.copy()
    except FileNotFoundError:
        print(f"{file_path} not found. Creating new file with default header.")
        header = HEADER_LINES.copy()
        configs = set()
    return header, configs

def save_configs(header: List[str], configs: Set[str], file_path: str) -> None:
    """Write header lines first, then each config on its own line."""
    with open(file_path, 'w', encoding='utf-8') as f:
        for line in header:
            f.write(line + '\n')
        # Optionally add a blank line to separate header from configs (optional)
        # f.write('\n')
        for cfg in sorted(configs):
            f.write(cfg + '\n')
    print(f"Saved {len(configs)} configs to {file_path} (header preserved).")

# ---------- Subscription processing ----------
def process_subscription_link(link: str, collected_configs: Set[str]) -> None:
    link = clean_url(link)
    print(f"Processing: {link}")
    content = fetch_content(link)
    if not content:
        return
    if re.search(r'sub_\d+\.txt', content, re.IGNORECASE):
        print("  Detected YAML index. Extracting sub-links...")
        sub_links = extract_sub_links_from_yaml(content, link)
        for sub_link in sub_links:
            sub_content = fetch_content(sub_link)
            if sub_content:
                configs = decode_possible_base64(sub_content)
                for cfg in configs:
                    if test_config_alive(cfg):
                        collected_configs.add(cfg)
    else:
        configs = decode_possible_base64(content)
        for cfg in configs:
            if test_config_alive(cfg):
                collected_configs.add(cfg)

def load_subscription_links(subs_file: str) -> List[str]:
    links = []
    try:
        with open(subs_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    links.append(line)
    except FileNotFoundError:
        print(f"No {subs_file} found. Skipping.")
    return links

def main():
    # 1. Load existing file (separate header and configs)
    header, existing_configs = load_existing_configs(FILE_PATH)
    print(f"Loaded {len(existing_configs)} existing configs. Header has {len(header)} lines.")

    # 2. Define subscription links
    default_links = [
        "https://raw.githubusercontent.com/hiddify/hiddify-app/refs/heads/main/test.configs/mahsa#Mahsa",
        "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt#Anonymous",
        "https://raw.githubusercontent.com/hiddify/hiddify-app/refs/heads/main/test.configs/warp#Warp%20&%20Psiphon"
    ]
    additional_links = load_subscription_links(SUBS_FILE)
    all_links = default_links + additional_links
    print(f"Total subscription links to process: {len(all_links)}")

    # 3. Process all links and collect alive configs
    new_configs = set()
    for link in all_links:
        process_subscription_link(link, new_configs)

    print(f"Found {len(new_configs)} alive configs from subscriptions.")

    # 4. Merge: keep existing configs (we already have them) and add new ones
    # But we also need to re-test existing configs? Not necessary, but you can.
    # To keep only alive configs overall, we should test existing ones as well.
    # Let's test existing configs and only keep those alive.
    print("Testing existing configs for liveness...")
    alive_existing = set()
    for cfg in existing_configs:
        if test_config_alive(cfg):
            alive_existing.add(cfg)
    print(f"Alive existing configs: {len(alive_existing)} (removed {len(existing_configs) - len(alive_existing)} dead ones).")

    # Merge alive existing with new alive configs
    merged_configs = alive_existing.union(new_configs)
    print(f"Merged configs: {len(merged_configs)} total (added {len(merged_configs) - len(alive_existing)} new ones).")

    # 5. Save back to file, preserving header
    save_configs(header, merged_configs, FILE_PATH)

if __name__ == "__main__":
    main()
