import base64
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================
# Configuration
# =========================
OUTPUT_FILE = "live_v2ray"
STATE_FILE = "state.json"
SOURCE_URL = "https://raw.githubusercontent.com/Abdulhossein/All-in-One/main/v2rays"
XRAY_BIN = os.path.join("xray-bin", "xray")
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
HTTP_TEST_TIMEOUT = 8
PROCESS_START_WAIT = 1.8
TCP_TEST_TIMEOUT = 3.0
START_PORT = 2080
MAX_WORKERS = 10
BATCH_SIZE = 200
MAX_RUNTIME_SECONDS = 55 * 60  # 55 minutes

HEADER_LINES = [
    "#profile-title: base64:TXkgdjJyYXkgTGl2ZSBDb2xsZWN0aW9u",
    "#profile-update-interval: 1",
    "#subscription-userinfo: upload=29; download=12; total=10737418240000000; expire=2546249531",
    "#support-url: https://github.com/Abdulhossein/All-in-One/",
    "#profile-web-page-url: https://github.com/Abdulhossein/All-in-One/edit/main/live_v2ray"
]

VALID_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "socks://")
TEST_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
]

# =========================
# Network session
# =========================
def create_session_with_retries(retries: int = 3, backoff_factor: float = 0.5) -> requests.Session:
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

def is_proxy_line(line: str) -> bool:
    return line.strip().startswith(VALID_SCHEMES)

def sanitize_config_lines(lines: List[str]) -> List[str]:
    cleaned = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if is_proxy_line(line):
            cleaned.append(line)
    return cleaned

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

def gather_configs_from_source(url: str) -> List[str]:
    """Fetch and decode all configs from a single source URL."""
    content = fetch_content(url)
    if not content:
        return []
    return decode_possible_base64(content)

def dedupe_keep_order(items: List[str]) -> List[str]:
    result = []
    seen = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result

def parse_query(query: str) -> Dict[str, str]:
    return dict(parse_qsl(query, keep_blank_values=True))

def parse_alpn(value: str) -> List[str]:
    return [x.strip() for x in value.split(",") if x.strip()]

def parse_host_port(host_port: str) -> Tuple[str, int]:
    host, port = host_port.rsplit(":", 1)
    return host, int(port)

# =========================
# Fast TCP precheck
# =========================
def parse_server_from_config(config: str) -> Optional[Tuple[str, int]]:
    try:
        config = config.strip()
        if config.startswith("vmess://"):
            payload = config[len("vmess://"):]
            decoded = try_b64decode(payload)
            if not decoded:
                return None
            data = json.loads(decoded)
            host = data.get("add")
            port = data.get("port")
            if host and port:
                return host, int(port)
        elif config.startswith(("vless://", "trojan://", "socks://")):
            parsed = urlparse(config)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
        elif config.startswith("ss://"):
            rest = config[len("ss://"):]
            rest = rest.split("#", 1)[0].split("?", 1)[0]
            if "@" in rest:
                host, port = parse_host_port(rest.split("@", 1)[1])
                return host, port
            decoded = try_b64decode(rest)
            if decoded and "@" in decoded:
                host, port = parse_host_port(decoded.split("@", 1)[1])
                return host, port
    except Exception as e:
        print(f"Parse error: {e}")
    return None

def tcp_ping(config: str, timeout: float = TCP_TEST_TIMEOUT) -> Optional[float]:
    server = parse_server_from_config(config)
    if not server:
        return None
    host, port = server
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - start) * 1000
            return round(elapsed, 2)
    except Exception:
        return None

# =========================
# Xray outbound builders
# =========================
def parse_vmess_outbound(raw_config: str) -> Optional[Dict]:
    payload = raw_config[len("vmess://"):]
    decoded = try_b64decode(payload)
    if not decoded:
        return None
    data = json.loads(decoded)
    network = data.get("net", "tcp")
    tls_mode = data.get("tls", "")
    path = data.get("path", "") or "/"
    host_header = data.get("host", "")
    sni = data.get("sni", "")
    alpn = data.get("alpn", "")
    stream_settings: Dict = {"network": network}
    if tls_mode == "tls":
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = {}
        if sni:
            stream_settings["tlsSettings"]["serverName"] = sni
        if alpn:
            stream_settings["tlsSettings"]["alpn"] = parse_alpn(alpn)
    else:
        stream_settings["security"] = "none"
    if network == "ws":
        stream_settings["wsSettings"] = {"path": path, "headers": {}}
        if host_header:
            stream_settings["wsSettings"]["headers"]["Host"] = host_header
    if network == "grpc":
        stream_settings["grpcSettings"] = {"serviceName": data.get("path", "")}
    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": data["add"],
                "port": int(data["port"]),
                "users": [{
                    "id": data["id"],
                    "alterId": int(data.get("aid", 0)),
                    "security": data.get("scy", "auto"),
                    "level": 0
                }]
            }]
        },
        "streamSettings": stream_settings
    }
    return outbound

def parse_vless_outbound(raw_config: str) -> Optional[Dict]:
    parsed = urlparse(raw_config)
    query = parse_query(parsed.query)
    stream_settings: Dict = {
        "network": query.get("type", "tcp"),
        "security": query.get("security", "none")
    }
    if query.get("security") == "tls":
        stream_settings["tlsSettings"] = {}
        if query.get("sni"):
            stream_settings["tlsSettings"]["serverName"] = query["sni"]
        if query.get("alpn"):
            stream_settings["tlsSettings"]["alpn"] = parse_alpn(query["alpn"])
        if query.get("fp"):
            stream_settings["tlsSettings"]["fingerprint"] = query["fp"]
    if query.get("security") == "reality":
        stream_settings["realitySettings"] = {
            "serverName": query.get("sni", ""),
            "publicKey": query.get("pbk", ""),
            "shortId": query.get("sid", ""),
            "fingerprint": query.get("fp", "chrome"),
            "spiderX": query.get("spx", "")
        }
    if query.get("type") == "ws":
        stream_settings["wsSettings"] = {
            "path": query.get("path", "/"),
            "headers": {}
        }
        if query.get("host"):
            stream_settings["wsSettings"]["headers"]["Host"] = query["host"]
    if query.get("type") == "grpc":
        stream_settings["grpcSettings"] = {"serviceName": query.get("serviceName", "")}
    if query.get("type") == "httpupgrade":
        stream_settings["httpupgradeSettings"] = {
            "path": query.get("path", "/"),
            "host": query.get("host", "")
        }
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "users": [{
                    "id": parsed.username,
                    "encryption": query.get("encryption", "none"),
                    "flow": query.get("flow", ""),
                    "level": 0
                }]
            }]
        },
        "streamSettings": stream_settings
    }

def parse_trojan_outbound(raw_config: str) -> Optional[Dict]:
    parsed = urlparse(raw_config)
    query = parse_query(parsed.query)
    stream_settings: Dict = {
        "network": query.get("type", "tcp"),
        "security": query.get("security", "tls")
    }
    if query.get("security", "tls") == "tls":
        stream_settings["tlsSettings"] = {}
        if query.get("sni"):
            stream_settings["tlsSettings"]["serverName"] = query["sni"]
        if query.get("alpn"):
            stream_settings["tlsSettings"]["alpn"] = parse_alpn(query["alpn"])
        if query.get("fp"):
            stream_settings["tlsSettings"]["fingerprint"] = query["fp"]
    if query.get("type") == "ws":
        stream_settings["wsSettings"] = {"path": query.get("path", "/"), "headers": {}}
        if query.get("host"):
            stream_settings["wsSettings"]["headers"]["Host"] = query["host"]
    if query.get("type") == "grpc":
        stream_settings["grpcSettings"] = {"serviceName": query.get("serviceName", "")}
    if query.get("type") == "httpupgrade":
        stream_settings["httpupgradeSettings"] = {
            "path": query.get("path", "/"),
            "host": query.get("host", "")
        }
    return {
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "password": parsed.username,
                "level": 0
            }]
        },
        "streamSettings": stream_settings
    }

def parse_ss_outbound(raw_config: str) -> Optional[Dict]:
    rest = raw_config[len("ss://"):]
    rest = rest.split("#", 1)[0]
    plugin_query = ""
    if "?" in rest:
        rest, plugin_query = rest.split("?", 1)
    if "@" in rest:
        creds, host_port = rest.split("@", 1)
    else:
        decoded = try_b64decode(rest)
        if not decoded or "@" not in decoded:
            return None
        creds, host_port = decoded.split("@", 1)
    method, password = creds.split(":", 1)
    host, port = parse_host_port(host_port)
    server = {
        "address": host,
        "port": int(port),
        "method": method,
        "password": password,
        "level": 0
    }
    if plugin_query:
        plugin_params = parse_query(plugin_query)
        if plugin_params.get("plugin"):
            server["plugin"] = plugin_params["plugin"]
        if plugin_params.get("plugin-opts"):
            server["pluginOpts"] = plugin_params["plugin-opts"]
    return {"protocol": "shadowsocks", "settings": {"servers": [server]}}

def parse_socks_outbound(raw_config: str) -> Optional[Dict]:
    parsed = urlparse(raw_config)
    server: Dict = {"address": parsed.hostname, "port": parsed.port}
    if parsed.username or parsed.password:
        server["users"] = [{"user": parsed.username or "", "pass": parsed.password or ""}]
    return {"protocol": "socks", "settings": {"servers": [server]}}

def parse_to_xray_outbound(raw_config: str) -> Optional[Dict]:
    try:
        if raw_config.startswith("vmess://"):
            return parse_vmess_outbound(raw_config)
        if raw_config.startswith("vless://"):
            return parse_vless_outbound(raw_config)
        if raw_config.startswith("trojan://"):
            return parse_trojan_outbound(raw_config)
        if raw_config.startswith("ss://"):
            return parse_ss_outbound(raw_config)
        if raw_config.startswith("socks://"):
            return parse_socks_outbound(raw_config)
    except Exception as e:
        print(f"Failed to convert config to Xray outbound: {e}")
    return None

# =========================
# Xray live test
# =========================
def find_free_port(start_port: int = START_PORT) -> int:
    for port in range(start_port, start_port + 2000):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise RuntimeError("No free port found")

def run_xray_and_measure(raw_config: str) -> Optional[float]:
    outbound = parse_to_xray_outbound(raw_config)
    if not outbound:
        return None
    socks_port = find_free_port()
    config_data = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": False}
        }],
        "outbounds": [
            dict(outbound, tag="proxy"),
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{
                "type": "field",
                "inboundTag": ["socks-in"],
                "outboundTag": "proxy"
            }]
        }
    }
    temp_dir = tempfile.mkdtemp(prefix="xray_live_")
    config_path = os.path.join(temp_dir, "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, ensure_ascii=False)
    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-config", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(PROCESS_START_WAIT)
        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        best_delay = None
        for test_url in TEST_URLS:
            start = time.perf_counter()
            try:
                response = requests.get(
                    test_url,
                    proxies=proxies,
                    timeout=HTTP_TEST_TIMEOUT,
                    headers={"User-Agent": USER_AGENT},
                    allow_redirects=True,
                )
                if response.status_code in (200, 204):
                    delay = round((time.perf_counter() - start) * 1000, 2)
                    if best_delay is None or delay < best_delay:
                        best_delay = delay
            except Exception:
                continue
        return best_delay
    except Exception as e:
        print(f"Xray execution failed: {e}")
        return None
    finally:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        shutil.rmtree(temp_dir, ignore_errors=True)

# =========================
# State management
# =========================
def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_state(state: dict):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)

def initialize_state() -> dict:
    """Fetch all configs from source and initialize state."""
    print("Fetching all configs from source...")
    configs = gather_configs_from_source(SOURCE_URL)
    configs = dedupe_keep_order(configs)
    print(f"Total unique configs: {len(configs)}")
    state = {
        "all_configs": configs,
        "last_index": -1,
        "batch_size": BATCH_SIZE,
        "finished": False,
        "active_added_total": 0
    }
    save_state(state)
    return state

# =========================
# Output file handling
# =========================
def ensure_header():
    """Write header to output file if it doesn't exist or is empty."""
    if not os.path.exists(OUTPUT_FILE) or os.path.getsize(OUTPUT_FILE) == 0:
        with open(OUTPUT_FILE, 'w') as f:
            for line in HEADER_LINES:
                f.write(line + '\n')

def append_configs(configs: List[str]):
    """Append configs to output file."""
    with open(OUTPUT_FILE, 'a') as f:
        for cfg in configs:
            f.write(cfg + '\n')

# =========================
# Main
# =========================
def main():
    if not os.path.isfile(XRAY_BIN):
        raise FileNotFoundError(f"Xray binary not found: {XRAY_BIN}")

    start_time = time.time()
    ensure_header()

    # Load or initialize state
    state = load_state()
    if not state:
        state = initialize_state()
    else:
        print(f"Resuming from state: last_index={state['last_index']}")

    all_configs = state['all_configs']
    last_index = state['last_index']
    batch_size = state['batch_size']
    finished = state.get('finished', False)

    if finished:
        print("All configs have been processed in previous runs. Exiting.")
        return

    start_idx = last_index + 1
    remaining_configs = all_configs[start_idx:]
    print(f"Configs remaining to test: {len(remaining_configs)}")

    if not remaining_configs:
        print("No more configs to process. Marking as finished.")
        state['finished'] = True
        save_state(state)
        return

    active_added_this_run = 0
    newly_active = []

    for i, cfg in enumerate(remaining_configs, start=start_idx):
        # Check time limit
        if time.time() - start_time > MAX_RUNTIME_SECONDS:
            print("Time limit reached. Saving state and exiting.")
            break

        # TCP precheck
        tcp_result = tcp_ping(cfg)
        if tcp_result is None:
            state['last_index'] = i
            continue

        # Xray test
        real_delay = run_xray_and_measure(cfg)
        if real_delay is not None:
            print(f"Active config found: {cfg[:60]}...")
            newly_active.append(cfg)
            active_added_this_run += 1
            state['active_added_total'] = state.get('active_added_total', 0) + 1
            # Append to output file immediately
            append_configs([cfg])
            # Check batch limit for this run
            if active_added_this_run >= batch_size:
                print(f"Reached batch limit of {batch_size} active configs. Stopping.")
                state['last_index'] = i
                save_state(state)
                return

        state['last_index'] = i
        # Save state periodically
        if i % 50 == 0:
            save_state(state)
            print(f"Progress: {i - start_idx + 1}/{len(remaining_configs)} tested, active this run: {active_added_this_run}")

    # If loop finishes naturally, mark as finished
    if state['last_index'] >= len(all_configs) - 1:
        state['finished'] = True
        print("All configs processed.")
    save_state(state)
    print(f"Run complete. Active configs added this run: {len(newly_active)}")

if __name__ == "__main__":
    main()
