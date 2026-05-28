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
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================
# Configuration
# =========================
OUTPUT_FILE = "live_v2ray"
SUBS_FILE = "subscriptions.txt"
XRAY_BIN = os.path.join("xray-bin", "xray")
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
HTTP_TEST_TIMEOUT = 8
PROCESS_START_WAIT = 1.8
TCP_TEST_TIMEOUT = 3.0
START_PORT = 2080
MAX_WORKERS = 10  # تعداد نخ‌های موازی برای تست TCP
BATCH_SIZE = 200  # ذخیره‌سازی مرحله‌ای هر ۲۰۰ کانفیگ فعال

HEADER_LINES = [
    "#profile-title: base64:TXkgdjJyYXkgTGl2ZSBDb2xsZWN0aW9u",
    "#profile-update-interval: 1",
    "#subscription-userinfo: upload=29; download=12; total=10737418240000000; expire=2546249531",
    "#support-url: https://github.com/Abdulhossein/All-in-One/",
    "#profile-web-page-url: https://github.com/Abdulhossein/All-in-One/edit/main/live_v2ray"
]

DEFAULT_LINKS = [
    "https://raw.githubusercontent.com/hiddify/hiddify-app/refs/heads/main/test.configs/mahsa#Mahsa",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt#Anonymous",
    "https://raw.githubusercontent.com/hiddify/hiddify-app/refs/heads/main/test.configs/warp#Warp%20&%20Psiphon"
]

VALID_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "socks://")
SUB_LINK_PATTERN = r'(https?://[^\s"\']+sub_\d+\.txt[^\s"\']*)'
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
# Helpers (دست‌نخورده باقی مانده‌اند)
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

def extract_sub_links_from_yaml(content: str, base_url: str) -> List[str]:
    found = re.findall(SUB_LINK_PATTERN, content)
    if found:
        return sorted(set(found))
    sub_names = re.findall(r"sub_(\d+)\.txt", content)
    return [urljoin(base_url, f"sub_{n}.txt") for n in sorted(set(sub_names), key=int)]

def load_subscription_links(subs_file: str) -> List[str]:
    links = []
    seen = set()
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

def gather_all_subscription_links() -> List[str]:
    all_links = []
    seen = set()
    for link in DEFAULT_LINKS + load_subscription_links(SUBS_FILE):
        normalized = clean_url(link)
        if normalized and normalized not in seen:
            seen.add(normalized)
            all_links.append(normalized)
    return all_links

def gather_configs_from_link(link: str) -> List[str]:
    content = fetch_content(link)
    if not content:
        return []
    if re.search(r"sub_\d+\.txt", content, re.IGNORECASE):
        all_configs = []
        for sub_link in extract_sub_links_from_yaml(content, link):
            sub_content = fetch_content(sub_link)
            if not sub_content:
                continue
            all_configs.extend(decode_possible_base64(sub_content))
        return all_configs
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
# Fast TCP precheck (موازی‌سازی شده)
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

def parallel_tcp_filter(configs: List[str]) -> List[Tuple[str, float]]:
    """
    تست موازی TCP روی تمام کانفیگ‌ها.
    تنها کانفیگ‌هایی که پاسخ دهند بازگردانده می‌شوند.
    """
    alive = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_config = {executor.submit(tcp_ping, cfg): cfg for cfg in configs}
        for future in as_completed(future_to_config):
            cfg = future_to_config[future]
            try:
                delay = future.result()
                if delay is not None:
                    alive.append((cfg, delay))
            except Exception as e:
                print(f"TCP test error for {cfg[:40]}...: {e}")
    alive.sort(key=lambda x: x[1])
    return alive

# =========================
# Xray outbound builders (دست‌نخورده باقی مانده‌اند)
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
    stream_settings: Dict = {
        "network": network
    }
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
        stream_settings["wsSettings"] = {
            "path": path,
            "headers": {}
        }
        if host_header:
            stream_settings["wsSettings"]["headers"]["Host"] = host_header
    if network == "grpc":
        stream_settings["grpcSettings"] = {
            "serviceName": data.get("path", "")
        }
    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": data["add"],
                    "port": int(data["port"]),
                    "users": [
                        {
                            "id": data["id"],
                            "alterId": int(data.get("aid", 0)),
                            "security": data.get("scy", "auto"),
                            "level": 0
                        }
                    ]
                }
            ]
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
        stream_settings["grpcSettings"] = {
            "serviceName": query.get("serviceName", "")
        }
    if query.get("type") == "httpupgrade":
        stream_settings["httpupgradeSettings"] = {
            "path": query.get("path", "/"),
            "host": query.get("host", "")
        }
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "users": [
                        {
                            "id": parsed.username,
                            "encryption": query.get("encryption", "none"),
                            "flow": query.get("flow", ""),
                            "level": 0
                        }
                    ]
                }
            ]
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
        stream_settings["wsSettings"] = {
            "path": query.get("path", "/"),
            "headers": {}
        }
        if query.get("host"):
            stream_settings["wsSettings"]["headers"]["Host"] = query["host"]
    if query.get("type") == "grpc":
        stream_settings["grpcSettings"] = {
            "serviceName": query.get("serviceName", "")
        }
    if query.get("type") == "httpupgrade":
        stream_settings["httpupgradeSettings"] = {
            "path": query.get("path", "/"),
            "host": query.get("host", "")
        }
    return {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "password": parsed.username,
                    "level": 0
                }
            ]
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
    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [server]
        }
    }

def parse_socks_outbound(raw_config: str) -> Optional[Dict]:
    parsed = urlparse(raw_config)
    server: Dict = {
        "address": parsed.hostname,
        "port": parsed.port
    }
    if parsed.username or parsed.password:
        server["users"] = [
            {
                "user": parsed.username or "",
                "pass": parsed.password or ""
            }
        ]
    return {
        "protocol": "socks",
        "settings": {
            "servers": [server]
        }
    }

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
# Xray live test (با مدیریت بهتر منابع)
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
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False}
            }
        ],
        "outbounds": [
            dict(outbound, tag="proxy"),
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["socks-in"],
                    "outboundTag": "proxy"
                }
            ]
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
# Output (بازنویسی کامل فایل)
# =========================
def save_configs(real_working: List[str], tcp_alive_only: List[str]) -> None:
    """
    فایل خروجی را از ابتدا بازنویسی می‌کند (حالت 'w').
    """
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for line in HEADER_LINES:
            f.write(line + "\n")
        for cfg in real_working:
            f.write(cfg + "\n")
        for cfg in tcp_alive_only:
            f.write(cfg + "\n")
    print(f"Saved {len(real_working)} real + {len(tcp_alive_only)} TCP configs to {OUTPUT_FILE}")

# =========================
# Main (بازنویسی شده با قابلیت‌های جدید)
# =========================
def main() -> None:
    if not os.path.isfile(XRAY_BIN):
        raise FileNotFoundError(f"Xray binary not found: {XRAY_BIN}")

    # 1. جمع‌آوری لینک‌ها و کانفیگ‌ها
    links = gather_all_subscription_links()
    print(f"Total subscription links: {len(links)}")

    raw_configs: List[str] = []
    for link in links:
        print(f"Fetching configs from: {link}")
        raw_configs.extend(gather_configs_from_link(link))

    raw_configs = dedupe_keep_order(raw_configs)
    print(f"Total unique configs collected: {len(raw_configs)}")

    # 2. فیلتر سریع اولیه با تست TCP موازی
    print("Running parallel TCP precheck...")
    tcp_alive = parallel_tcp_filter(raw_configs)
    print(f"TCP alive configs: {len(tcp_alive)}/{len(raw_configs)}")

    # 3. تست نهایی با Xray و ذخیره‌سازی مرحله‌ای
    real_working = []
    processed_count = 0
    for idx, (cfg, tcp_delay) in enumerate(tcp_alive, start=1):
        print(f"[{idx}/{len(tcp_alive)}] Testing config with Xray...")
        real_delay = run_xray_and_measure(cfg)
        if real_delay is not None:
            print(f"  REAL OK: {real_delay} ms")
            real_working.append(cfg)
            processed_count += 1
            # ذخیره‌سازی مرحله‌ای پس از هر ۲۰۰ کانفیگ فعال
            if processed_count % BATCH_SIZE == 0:
                print(f"Checkpoint: {processed_count} active configs found. Saving...")
                save_configs(real_working, [])
        else:
            print(f"  TCP only: {tcp_delay} ms (Xray failed)")

    # 4. ذخیره نهایی
    print(f"Total real working configs: {len(real_working)}")
    print(f"Total TCP only configs: {len(tcp_alive) - len(real_working)}")
    save_configs(real_working, [])

if __name__ == "__main__":
    main()
