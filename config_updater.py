import requests
import base64
import re
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import List, Set, Optional

# ----- Configuration -----
FILE_PATH = "v2rays"          # مسیر فایل اصلی در مخزن
SUBS_FILE = "subscriptions.txt" # فایل حاوی لینک‌های اضافی
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
# -------------------------

def clean_url(url: str) -> str:
    """Remove fragment (#...) and extra spaces from a URL."""
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
    """Download content from a URL with retries and timeout."""
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
    """If the text looks like base64 (no vmess:// etc.), decode it."""
    text = text.strip()
    # If already contains config lines, return as is
    if re.search(r'^(vmess|vless|trojan|ss|socks)://', text, re.MULTILINE):
        return [line for line in text.splitlines() if line.strip()]

    # Try base64 decode
    try:
        decoded = base64.b64decode(text).decode('utf-8')
        if re.search(r'^(vmess|vless|trojan|ss|socks)://', decoded, re.MULTILINE):
            return [line for line in decoded.splitlines() if line.strip()]
        else:
            return [line for line in text.splitlines() if line.strip()]
    except Exception:
        return [line for line in text.splitlines() if line.strip()]

def extract_sub_links_from_yaml(content: str, base_url: str) -> List[str]:
    """Extract sub_*.txt URLs from a YAML-style content."""
    pattern = r'(https?://[^\s"\']+sub_\d+\.txt[^\s"\']*)'
    found = re.findall(pattern, content)
    if not found:
        sub_names = re.findall(r'sub_(\d+)\.txt', content)
        found = [urljoin(base_url, f'sub_{n}.txt') for n in set(sub_names)]
    return found

def process_subscription_link(link: str, collected_configs: Set[str]) -> None:
    """Process one subscription link and add configs to the set."""
    link = clean_url(link)
    print(f"Processing: {link}")
    content = fetch_content(link)
    if not content:
        return

    # Check for YAML index (contains sub_*.txt)
    if re.search(r'sub_\d+\.txt', content, re.IGNORECASE):
        print("Detected YAML index. Extracting sub-links...")
        sub_links = extract_sub_links_from_yaml(content, link)
        for sub_link in sub_links:
            sub_content = fetch_content(sub_link)
            if sub_content:
                configs = decode_possible_base64(sub_content)
                collected_configs.update(configs)
    else:
        # Direct subscription content
        configs = decode_possible_base64(content)
        collected_configs.update(configs)

def load_existing_configs(file_path: str) -> Set[str]:
    """Load existing configs from the file."""
    configs = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    configs.add(line)
    except FileNotFoundError:
        print(f"File {file_path} not found. Creating new one.")
    return configs

def save_configs(configs: Set[str], file_path: str) -> None:
    """Save configs to the file."""
    with open(file_path, 'w', encoding='utf-8') as f:
        for cfg in sorted(configs):
            f.write(cfg + '\n')
    print(f"Saved {len(configs)} configs to {file_path}")

def load_subscription_links(subs_file: str) -> List[str]:
    """Load additional subscription links from a text file (one per line)."""
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
    # 1. Load existing configs
    existing_configs = load_existing_configs(FILE_PATH)
    print(f"Loaded {len(existing_configs)} existing configs.")

    # 2. Define subscription links
    # Default links (you can modify this list)
    default_links = [
        "https://raw.githubusercontent.com/hiddify/hiddify-app/refs/heads/main/test.configs/mahsa#Mahsa",
        "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt#Anonymous",
        "https://raw.githubusercontent.com/hiddify/hiddify-app/refs/heads/main/test.configs/warp#Warp%20&%20Psiphon"
    ]

    # Load additional links from subscriptions.txt if exists
    additional_links = load_subscription_links(SUBS_FILE)
    
    all_links = default_links + additional_links
    print(f"Total subscription links to process: {len(all_links)}")

    # 3. Process all links and collect new configs
    new_configs = set()
    for link in all_links:
        process_subscription_link(link, new_configs)

    print(f"Found {len(new_configs)} new configs from subscriptions.")

    # 4. Merge with existing configs (keep existing, add new ones)
    merged_configs = existing_configs.union(new_configs)
    print(f"Merged configs: {len(merged_configs)} total (added {len(merged_configs) - len(existing_configs)} new ones).")

    # 5. Save merged configs back to the file
    save_configs(merged_configs, FILE_PATH)

if __name__ == "__main__":
    main()
