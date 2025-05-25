# OrynAudit

> **"The system doesn't lie. It just forgets. This script reminds it what it's hiding."**

[![License: MIT](https://img.shields.io/badge/License-MIT-gray.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-darkgreen.svg)](https://www.gnu.org/software/bash/)
[![NixOS](https://img.shields.io/badge/NixOS-Compatible-blueviolet.svg)](https://nixos.org/)
[![Security](https://img.shields.io/badge/Security-Audit-red.svg)]()

---

**System Confessional Script for NixOS & Linux Machines**

OrynAudit is a surgical-grade audit tool. 
Not just a scanner. Not just a checklist. 
It interrogates your system with colour-coded precision, aesthetic clarity, and markdown-ready output.

It doesn't just tell you what you installed. 
**It tells you what you forgot.**

## ✨ Features

```
🔴 HIGH     🟡 MEDIUM     🔵 INFO     ✅ GOOD
```

- **🔐 User & Privilege Analysis** — Who has the keys to your castle?
- **🔌 Network Exposure Mapping** — Every port, every service, every risk
- **🔍 DNS Leak Detection** — Your queries might be louder than you think
- **🧬 SUID Binary Forensics** — The elevated executables hiding in plain sight
- **🧠 System State Snapshot** — Memory, disk, processes, the whole truth
- **📊 Markdown Report Generation** — Clean, timestamped, shareable
- **🎨 Enhanced Terminal Output** — Optional `bat`/`rich` integration for beauty

## 🚀 Quick Start

**One-liner with full environment:**

```bash
git clone https://github.com/OrynVail/oryn-audit.git
cd oryn-audit
nix-shell
chmod +x oryn_audit.sh
sudo ./oryn_audit.sh
```

**Minimal run (core utilities required):**

```bash
sudo ./oryn_audit.sh
```

## 📸 Sample Output

Want to see what it looks like before running it?  
→ [**View Sample Report**](./oryn_audit_sample.md)

## 🔍 Audit Scope

<details>
<summary><strong>Click to expand full audit checklist</strong></summary>

### Security & Permissions
- SUID/SGID binaries and ownership analysis
- World-writable files and unowned resources
- User accounts with login shells
- Sudo privilege escalation paths

### Network & Services  
- Open TCP/UDP ports with process mapping
- DNS configuration and leak testing
- Startup services and failed daemons
- Root processes and resource consumption

### System Health
- Memory and disk utilization
- CPU vulnerabilities and mitigations 
- Kernel parameters and hardening
- Container/VM environment detection

### NixOS Specific
- Store integrity and daemon status
- Declarative configuration insights
- Generation analysis and cleanup opportunities

</details>

## 🎯 Philosophy

This script isn't forged for the cold comfort of compliance checkboxes.  
It's tempered to pierce the fog of system state, answering the singular question:

> **"What symphony, or cacophony, truly plays within this machine?"**

It's a lens, not a spy. It phones no home, hides no motive.  
It simply offers clarity—and meticulously archives the truth it unveils.

## 🛠️ Dependencies

**Core requirements:**
- Bash 4.0+
- Standard Unix utilities (`ss`, `find`, `ps`, `grep`, `awk`)
- Root privileges for comprehensive scanning

**Optional enhancements:**
- [`bat`](https://github.com/sharkdp/bat) — Syntax-highlighted report viewing
- [`rich`](https://github.com/Textualize/rich-cli) — Beautiful terminal formatting
- [`dig`](https://linux.die.net/man/1/dig) — DNS leak detection

*The included `shell.nix` provides everything automatically.*

## 📋 Usage Examples

**Basic system audit:**
```bash
sudo ./oryn_audit.sh
```

**View generated report:**
```bash
bat /tmp/oryn_audit-*.md  # With bat installed
# or
cat /tmp/oryn_audit-*.md  # Plain text
```

**Automated daily audits:**
```bash
# Add to crontab for daily 3 AM audits
0 3 * * * /path/to/oryn_audit.sh > /var/log/oryn_audit.log 2>&1
```

## 🤝 Contributing

Found a missing security check? System quirk it should catch?

**All I ask: if you make it better—make it yours.**

## 📜 License

MIT License — Use it, remix it, port it. Burn it into your bootloader if you must. 

See [LICENSE](./LICENSE) for full details.

## 👤 Author

**Oryn** 
*"A system isn't secure until it's uncomfortable in your presence."*

---

<div align="center">

**[⭐ Star this repo](https://github.com/OrynVail/oryn-audit) if OrynAudit helped reveal your system's secrets**

</div>
