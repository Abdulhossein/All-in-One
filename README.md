# All-in-One Proxy Configs

This repository automatically gathers and updates working proxy configurations from various free sources.  
It runs on a schedule to keep the configs fresh and usable.

## How to Use

Simply copy the subscription links below and paste it into your VPN client (like Hiddify, V2RayN, V2RayNG, Streisand, Fair VPN, etc.):

```

https://raw.githubusercontent.com/Abdulhossein/All-in-One/main/v2rays

```
```
https://raw.githubusercontent.com/Abdulhossein/All-in-One/main/live_v2rays
```

That's it – your client will automatically fetch the latest working servers.

## Automation

A GitHub Action triggers every **3 days** to update the config list. It works like this:

1. Fetches all proxy configs from the source.
2. Runs a fast TCP check to filter out dead servers immediately.
3. Tests the remaining candidates with **Xray** to verify real connectivity.
4. Appends up to **200 live configs** per run to `the final files`, then stops.
5. Resumes from where it left off in the next scheduled run.
6. When all configs have been tested (or every 10 days), the list **resets** – old configs are cleared and a fresh batch is created.

This keeps the subscription link small, responsive, and always filled with working servers.

---

*No manual configuration needed. The list is maintained automatically.*
```
