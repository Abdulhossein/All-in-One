import base64
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================
# Configuration
# =========================
OUTPUT_FILE = "live_v2ray"
SUBS_FILE = "subscriptions.txt"
XRAY_BIN = os.path.join("xray-bin", "xray")
XRAY_TIMEOUT = 12
HTTP_TEST_TIMEOUT = 8
START_PORT = 2080
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

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
# HTTP session
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
# Basic helpers
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


def fetch_content(url: str) -> Optional[str]:
    try:
        response = SESSION.get(url, timeout=20, headers={"User-Agent": USER_AGENT})
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
                host_port = rest.split("@", 1)[1]
                host, port = host_port.rsplit(":", 1)
                return host, int(port)

            decoded = try_b64decode(rest)
            if decoded and "@" in decoded:
                host_port = decoded.split("@", 1)[1]
                host_port = host_port.split("#", 1)[0].split("?", 1)[0]
                host, port = host_port.rsplit(":", 1)
                return host, int(port)

    except Exception as e:
        print(f"Parse error: {e}")

    return None


def tcp_ping(config: str, timeout: float = 3.0) -> Optional[float]:
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
# Xray real test
# =========================
def find_free_port(start_port: int = START_PORT) -> int:
    port = start_port
    while port < start_port + 2000:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1
    raise RuntimeError("No free port found")


def build_xray_config(raw_config: str, socks_port: int) -> Dict:
    outbound = None

    if raw_config.startswith("vmess://"):
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": []
            },
            "streamSettings": {}
        }
    elif raw_config.startswith("vless://"):
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": []
            },
            "streamSettings": {}
        }
    elif raw_config.startswith("trojan://"):
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": []
            },
            "streamSettings": {}
        }
    elif raw_config.startswith("ss://"):
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": []
            },
            "streamSettings": {}
        }
    elif raw_config.startswith("socks://"):
        outbound = {
            "protocol": "socks",
            "settings": {
                "servers": []
            },
            "streamSettings": {}
        }
    else:
        raise ValueError("Unsupported protocol")

    return {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "udp": False
                }
            }
        ],
        "outbounds": [
            outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            }
        ]
    }


def parse_to_xray_outbound(raw_config: str) -> Optional[Dict]:
    try:
        if raw_config.startswith("vmess://"):
            payload = raw_config[len("vmess://"):]
            decoded = try_b64decode(payload)
            if not decoded:
                return None
            data = json.loads(decoded)

            network = data.get("net", "tcp")
            security = data.get("tls", "")
            path = data.get("path", "")
            host_header = data.get("host", "")
            sni = data.get("sni", "")
            alpn = data.get("alpn", "")

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
                "streamSettings": {
                    "network": network
                }
            }

            if security == "tls":
                outbound["streamSettings"]["security"] = "tls"
                outbound["streamSettings"]["tlsSettings"] = {}
                if sni:
                    outbound["streamSettings"]["tlsSettings"]["serverName"] = sni
                if alpn:
                    outbound["streamSettings"]["tlsSettings"]["alpn"] = alpn.split(",")

            if network == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": path or "/",
                    "headers": {}
                }
                if host_header:
                    outbound["streamSettings"]["wsSettings"]["headers"]["Host"] = host_header

            return outbound

        if raw_config.startswith("vless://"):
            parsed = urlparse(raw_config)
            query = dict(
                item.split("=", 1) for item in parsed.query.split("&") if "=" in item
            )

            outbound = {
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
                                    "flow": query.get("flow", "")
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": query.get("type", "tcp"),
                    "security": query.get("security", "none")
                }
            }

            if query.get("security") == "tls":
                outbound["streamSettings"]["tlsSettings"] = {}
                if query.get("sni"):
                    outbound["streamSettings"]["tlsSettings"]["serverName"] = query["sni"]
                if query.get("alpn"):
                    outbound["streamSettings"]["tlsSettings"]["alpn"] = query["alpn"].split(",")

            if query.get("type") == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": query.get("path", "/"),
                    "headers": {}
                }
                if query.get("host"):
                    outbound["streamSettings"]["wsSettings"]["headers"]["Host"] = query["host"]

            if query.get("type") == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": query.get("serviceName", "")
                }

            if query.get("security") == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": query.get("sni", ""),
                    "publicKey": query.get("pbk", ""),
                    "shortId": query.get("sid", ""),
                    "fingerprint": query.get("fp", "chrome"),
                    "spiderX": query.get("spx", "")
                }

            return outbound

        if raw_config.startswith("trojan://"):
            parsed = urlparse(raw_config)
            query = dict(
                item.split("=", 1) for item in parsed.query.split("&") if "=" in item
            )

            outbound = {
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
                "streamSettings": {
                    "network": query.get("type", "tcp"),
                    "security": query.get("security", "tls")
                }
            }

            if query.get("security", "tls") == "tls":
                outbound["streamSettings"]["tlsSettings"] = {}
                if query.get("sni"):
                    outbound["streamSettings"]["tlsSettings"]["serverName"] = query["sni"]
                if query.get("alpn"):
                    outbound["streamSettings"]["tlsSettings"]["alpn"] = query["alpn"].split(",")

            if query.get("type") == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": query.get("path", "/"),
                    "headers": {}
                }
                if query.get("host"):
                    outbound["streamSettings"]["wsSettings"]["headers"]["Host"] = query["host"]

            if query.get("type") == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": query.get("serviceName", "")
                }

            return outbound

        if raw_config.startswith("ss://"):
            rest = raw_config[len("ss://"):]
            rest = rest.split("#", 1)[0]
            plugin_part = ""
            if "?" in rest:
                rest, plugin_part = rest.split("?", 1)

            decoded = None
            if "@" not in rest:
                decoded = try_b64decode(rest)
                if not decoded:
                    return None
                rest = decoded

            creds, host_port = rest.split("@", 1)
            method, password = creds.split(":", 1)
            host, port = host_port.rsplit(":", 1)

            server = {
                "address": host,
                "port": int(port),
                "method": method,
                "password": password,
                "level": 0
            }

            outbound = {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [server]
                }
            }

            if plugin_part:
                params = dict(
                    item.split("=", 1) for item in plugin_part.split("&") if "=" in item
                )
                plugin = params.get("plugin", "")
                if plugin:
                    server["plugin"] = plugin
                    if "plugin-opts" in params:
                        server["pluginOpts"] = params["plugin-opts"]

            return outbound

        if raw_config.startswith("socks://"):
            parsed = urlparse(raw_config)
            return {
                "protocol": "socks",
                "settings": {
                    "servers": [
                        {
                            "address": parsed.hostname,
                            "port": parsed.port,
                            "users": [
                                {
                                    "user": parsed.username or "",
                                    "pass": parsed.password or ""
                                }
                            ] if parsed.username or parsed.password else []
                        }
                    ]
                }
            }

    except Exception as e:
        print(f"Failed to convert config to Xray outbound: {e}")
        return None

    return None


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

        time.sleep(1.8)

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
# Save output
# =========================
def save_configs(real_working: List[str], tcp_alive_only: List[str]) -> None:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for line in HEADER_LINES:
            f.write(line + "\n")
        for cfg in real_working:
            f.write(cfg + "\n")
        for cfg in tcp_alive_only:
            f.write(cfg + "\n")


# =========================
# Main
# =========================
def main() -> None:
    if not os.path.isfile(XRAY_BIN):
        raise FileNotFoundError(f"Xray binary not found: {XRAY_BIN}")

    links = gather_all_subscription_links()
    print(f"Total subscription links: {len(links)}")

    raw_configs = []
    for link in links:
        print(f"Fetching configs from: {link}")
        raw_configs.extend(gather_configs_from_link(link))

    raw_configs = dedupe_keep_order(raw_configs)
    print(f"Total unique configs collected: {len(raw_configs)}")

    real_results: List[Tuple[str, float]] = []
    tcp_results: List[Tuple[str, float]] = []

    for idx, cfg in enumerate(raw_configs, start=1):
        print(f"[{idx}/{len(raw_configs)}] Testing config...")

        tcp_delay = tcp_ping(cfg)
        if tcp_delay is None:
            print("  TCP failed")
            continue

        real_delay = run_xray_and_measure(cfg)
        if real_delay is not None:
            print(f"  REAL OK: {real_delay} ms")
            real_results.append((cfg, real_delay))
        else:
            print(f"  TCP only: {tcp_delay} ms")
            tcp_results.append((cfg, tcp_delay))

    real_results.sort(key=lambda x: x[1])
    tcp_results.sort(key=lambda x: x[1])

    real_working = [cfg for cfg, _ in real_results]
    tcp_alive_only = [cfg for cfg, _ in tcp_results]

    print(f"Real working configs: {len(real_working)}")
    print(f"TCP alive only configs: {len(tcp_alive_only)}")

    save_configs(real_working, tcp_alive_only)
    print(f"Saved output to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
