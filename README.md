# 🔍 ScanLine - OSINT Security Scanner

### Developed & Maintained by OSSiqn  
**OSINT Security Scanner v1.0.0**

---

## 🔧 Produced by OSSiqn
- 🐙 GitHub: https://github.com/ossiqntwo  

📜 **License:** MIT © 2024 OSSiqn — All rights reserved.

> This tool was developed by OSSiqn as a contribution to the global InfoSec community.

---

## 🇹🇷 Türkçe Açıklama

**ScanLine**, OSSiqn tarafından geliştirilen açık kaynaklı bir **OSINT güvenlik tarama aracıdır.**

### 🚀 Ne Yapar?

- 🔎 GitHub Code Search üzerinde unutulmuş API anahtarlarını, şifreleri ve gizli bilgileri tarar  
- 📋 Pastebin ve GitHub Gist üzerindeki veri sızıntılarını tespit eder  
- 🔐 SSL sertifika geçerlilik kontrolü yapar  
- 🛡️ HTTP güvenlik başlıklarını analiz eder  
- 💬 Discord ve Telegram üzerinden anlık bildirim gönderir  
- 🌐 Canlı web arayüzü ile sonuçları terminal temalı panelde gösterir  
- 🐳 Docker ile tek komutla kurulur  

---

### 👥 Kimler Kullanabilir?

- Güvenlik araştırmacıları  
- Pentest uzmanları  
- Bug bounty avcıları  
- Kurumsal güvenlik ekipleri  

---

### ⚠️ Yasal Uyarı

Bu araç yalnızca:

- Kendi sistemlerinizde  
- İzin verilmiş hedeflerde  
- Eğitim amaçlı  

kullanılmalıdır.

> İzinsiz erişim Türk Ceza Kanunu 243-244 kapsamında suçtur.

---

## 🇬🇧 English Description

**ScanLine** is an open-source **OSINT security scanning tool** developed and maintained by OSSiqn.

### 🚀 What Does It Do?

- 🔎 Scans GitHub Code Search for exposed API keys, passwords, and secrets  
- 📋 Detects leaks on Pastebin and GitHub Gists  
- 🔐 Validates SSL certificate expiry and integrity  
- 🛡️ Analyzes HTTP security headers  
- 💬 Sends real-time alerts via Discord & Telegram  
- 🌐 Displays results in a dark terminal-style web dashboard  
- 🐳 Docker-ready — deploys with a single command  

---

### 👥 Who Is It For?

- Security researchers  
- Penetration testers  
- Bug bounty hunters  
- Enterprise security teams  

---

### ⚠️ Legal Disclaimer

Use this tool only on:

- Systems you own  
- Targets you have explicit permission to test  
- Educational environments  

> Unauthorized access to systems is illegal.

---

## 🚀 Quick Start

### 🐳 Docker

```bash
git clone https://github.com/ossiqntwo/scanline
cd scanline
cp .env.example .env
nano .env
docker-compose up -d
🛠️ Manual
pip install -r requirements.txt
python src/main.py
🌐 Web Dashboard
http://localhost:5000
⚙️ Configuration
Variable	Description
GITHUB_TOKEN	GitHub Personal Access Token
DISCORD_WEBHOOK_URL	Discord notifications
TELEGRAM_BOT_TOKEN	Telegram bot token
TELEGRAM_CHAT_ID	Telegram chat/group ID
📊 Features
Feature	Status
GitHub Code Scanning	✅ Active
Pastebin Monitoring	✅ Active
GitHub Gist Scanning	✅ Active
SSL Certificate Check	✅ Active
HTTP Header Analysis	✅ Active
Discord Notifications	✅ Active
Telegram Notifications	✅ Active
Web Dashboard	✅ Active
Docker Support	✅ Active
Shodan Integration	🔄 Coming Soon
Censys Integration	🔄 Coming Soon
👤 Developer

OSSiqn Team

🐙 GitHub: https://github.com/ossiqntwo
📧 Contact: ossiqn@proton.me
📜 License

MIT License — © 2024 OSSiqn

This tool was developed by OSSiqn as a contribution to the InfoSec community.

⭐ If you like this project, don’t forget to star the repo!
