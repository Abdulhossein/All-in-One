Here's a complete README.md file for your repository. It includes your subscription link, explains the auto-update feature, and provides instructions for users.

```markdown
# All-in-One V2Ray Config Collection

![GitHub Actions](https://github.com/Abdulhossein/All-in-One/actions/workflows/update-configs.yml/badge.svg)

A curated, **automatically updated** collection of active V2Ray configuration links (VMess, VLess, Trojan, Shadowsocks, SOCKS).  
The config list is refreshed monthly (or on-demand) using GitHub Actions – only alive servers are kept.

---

## 📡 Subscription Link

Add this URL to your V2Ray client (e.g., V2RayNG, NekoBox, Streisand, ClashMeta):

```

https://raw.githubusercontent.com/Abdulhossein/All-in-One/main/v2rays

```

> **Note:** The file uses the standard base64 subscription format and includes a header with profile info, update interval, and user data.

---

## ✨ Features

- ✅ **Auto‑updated** – New configs are added, dead ones are removed every month.
- ✅ **Liveness tested** – Every config is tested via TCP connection before being included.
- ✅ **Header preserved** – Profile title, update interval, and support URL remain intact.
- ✅ **Multiple sources** – Aggregates from 3 default subscriptions + any you add.
- ✅ **Manual trigger** – You can run the update anytime from the Actions tab.
- ✅ **Custom links** – Add your own subscription URLs via `subscriptions.txt`.

---

## 🚀 How to Use

1. Copy the subscription link above.
2. Open your V2Ray client (e.g., V2RayNG).
3. Go to **Subscription Settings** → **+** → paste the link.
4. Set update interval to **1 day** (or as you wish).
5. Update manually or wait for auto‑sync.

---

## 🛠️ Adding Your Own Subscription Links

If you want to include extra sources, create a file named `subscriptions.txt` in the root of this repository and add one subscription URL per line:

```

https://your-subscription-link-1.txt
https://another-link.com/sub

```

The GitHub Action will automatically merge them during the next update.

---

## 🤖 GitHub Action Automation

The repository uses a scheduled GitHub Action:

- **Schedule:** Runs at 00:00 on the 1st day of every month.
- **Manual trigger:** From the **Actions** tab → **Update Configs** → **Run workflow**.
- **Live testing:** Each config is tested (TCP handshake, timeout 3s). Dead configs are removed.
- **Header:** The top lines (starting with `#`) are never touched.

You can also add new links on the fly when manually triggering the workflow – just fill the `new_subs` field with comma‑separated URLs.

---

## 📂 Repository Structure

```

.
├── v2rays                 # The final subscription file (auto‑generated)
├── config_updater.py      # Python script that fetches, tests & merges configs
├── subscriptions.txt      # (Optional) Extra subscription links
└── .github/workflows/
└── update-configs.yml # GitHub Action workflow

```

---

## 🙏 Credits

Configs are aggregated from public sources:

- [Hiddify test configs](https://github.com/hiddify/hiddify-app)
- [4n0nymou3 proxy fetcher](https://github.com/4n0nymou3/multi-proxy-config-fetcher)
- [MahsaFreeConfig](https://github.com/mahsanet/MahsaFreeConfig)

Special thanks to all free config providers.

---

## 📜 License

This project is for **educational purposes only**.  
Use at your own risk. The author is not responsible for any misuse.

---

## ⭐ Support

If you find this useful, consider starring the repository ⭐  
For issues or suggestions, open a ticket on GitHub.
```

---

📝 How to add this to your repository

1. Create a new file in your repository root named README.md.
2. Copy the entire content above into it.
3. Commit and push.

The subscription link points directly to your v2rays file. It will automatically stay up‑to‑date thanks to the GitHub Action you've already set up.

