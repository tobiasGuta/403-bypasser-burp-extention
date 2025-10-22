# 403-bypasser-burp-extention
Lightweight Jython Burp extension that spins up a self-contained Swing UI inside Extender to test path &amp; header payloads against 403 responses, no Burp Pro active scanner required. Fast to drop in, safe-by-default (scope checks + rate limiting), and built with Burp 
helpers so it’s robust, not hacky.

**Features**

-   Test common path + header bypass payloads against 403 responses.

-   Standalone worker thread with Start/Stop controls and configurable rate limit.

-   Results table + Repeater-style request/response viewers for easy triage.

-   Context menu: **Send to 403 Bypasser** for quick enqueueing.

-   Uses Burp helpers to build requests (avoids brittle `string.replace` hacks).

-   Safe defaults: scope checking, simple rate limiting, no auto-enqueue by default.

**Quick usage**\
Drop the file into Burp Extender (Python/Jython) -> open **Extender -> 403 Bypasser** -> enqueue requests or use context menu -> hit Start.

# Demo

https://github.com/user-attachments/assets/6516c85c-b7b2-45c5-a7c4-77afccc62d11

# Support
If my tool helped you land a bug bounty, consider buying me a coffee ☕️ as a small thank-you! Everything I build is free, but a little support helps me keep improving and creating more cool stuff ❤️
---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>

---
