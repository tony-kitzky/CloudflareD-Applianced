# CloudflareD-Applianced
Bash scripts to convert a standard, rpm-based Linux server into a bespoke appliance to run Cloudflare's CloudflareD tunnel daemon. The "applianced" server will run CloudflareD as a rootless container. Server OS must use Systemd and Network Manager (not systemd-networkd). Server requires two network adapters. Primary adapter (eth0) must have reachability to Cloudflare via Internet. CloudflareD origin/private traffic egresses the second adapter.

Vibe coded with ChatGPT 5.2 Thinking LLM on January 20, 2026.
* https://chatgpt.com/share/e/6965778b-c898-8001-b27d-209c0a5024f7

Install script and cloudflare private access tested using Alma Linux 9.6 virtual server in AWS EC2 on January 30, 2026.
