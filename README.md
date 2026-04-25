# R00tGlyph v2.0 - Enterprise Web Security Training Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-Educational-orange.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Training-red.svg)](README.md)

R00tGlyph v2.0 is a comprehensive, enterprise-grade web security training platform designed for security professionals, developers, and ethical hackers. Featuring 188 challenges across 9 vulnerability categories, team-based CTF play, admin panel, progressive hints, and detailed solutions.

## 🚀 **Features**

### **🎯 188 Challenges Across 9 Categories**
| Category | Levels | Difficulty Range | Description |
|----------|--------|-----------------|-------------|
| **XSS** | 1-30 | Beginner → Expert | Reflected, DOM, Stored, WAF bypass, CSP bypass, Prototype Pollution, and more |
| **SQLi** | 1-23 | Beginner → Expert | UNION, Blind, Time-based, WAF bypass, NoSQL, GraphQL, ORM injection |
| **CMDi** | 1-23 | Beginner → Expert | Basic, Filter bypass, Blind, JSON APIs, Container escapes |
| **CSRF** | 1-23 | Beginner → Expert | Form, JSON, SameSite bypass, OAuth, WebSocket, GraphQL mutations |
| **SSRF** | 1-23 | Beginner → Expert | Internal scanning, Cloud metadata, DNS rebinding, Protocol smuggling |
| **XXE** | 1-23 | Beginner → Expert | File disclosure, Blind, Billion Laughs, SOAP, OOB data retrieval |
| **SSTI** | 1-23 | Beginner → Expert | Jinja2, Twig, Freemarker, Sandbox escape, RCE |
| **Deserialization** | 1-10 | Beginner → Expert | Python pickle, PHP serialize, Java, .NET, YAML |
| **Auth Bypass** | 1-10 | Beginner → Expert | SQLi, JWT, Session fixation, OAuth, MFA bypass |

### **🏗️ Platform Features**
- **Global Scoreboard** - Compete with hackers worldwide; progress syncs to the central R00tGlyph server
- **Progressive Hint System** - Contextual hints that unlock per challenge
- **Detailed Solutions** - Step-by-step walkthroughs with prevention methods
- **Team-Based CTF** - Create/join teams, team scoreboard
- **Admin Panel** - Dashboard with analytics, user management, challenge toggling
- **Rate Limiting** - Anti-abuse protection on login and flag submissions
- **Real Command Execution** - Sandboxed command execution for realistic CMDi challenges
- **Flag System** - Unique per-user flags for each challenge
- **Profile Management** - Track progress, upload profile pictures
- **Interactive UI** - Live output console, payload reference, hint modals

## 📦 **Installation & Deployment**

### **🔧 Quick Start (Local Development)**

```bash
# Clone repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database and start
python run.py --dev
```

Access at: http://localhost:5000

### **🐳 Docker Deployment**

```bash
# Quick start
docker-compose up -d

# Development mode with Adminer
docker-compose --profile development up -d

# Production mode with PostgreSQL
docker-compose --profile production up -d
```

### **☁️ Cloud Deployment**

- **Render**: One-click deploy via `render.yaml`
- **Heroku**: Push to Heroku with `Procfile`
- **Any VPS**: Use `docker-compose.yml` or `gunicorn`

## 🎮 **Getting Started**

### **1. Create Account**
- Click "Register" and create your profile
- Your progress automatically syncs to the global scoreboard
- First user can be promoted to admin via the reset command

### **2. Choose Your Path**
- **Beginners**: Start with XSS Level 1 or SQLi Level 1
- **Intermediate**: Jump to filter bypass challenges
- **Advanced**: Try expert-level WAF bypasses and chained attacks

### **3. Challenge Workflow**
1. **Read the scenario** - Understand the vulnerable application context
2. **Analyze the code** - Use browser dev tools to identify vulnerabilities
3. **Craft your payload** - Develop and test your exploit
4. **Submit the flag** - Capture the flag to complete the challenge
5. **Review the solution** - Study the walkthrough and prevention methods

### **4. Using Hints**
Each challenge includes progressive hints accessible via the hint button or API:
```
GET /api/hints/<category>/<level>
```

### **5. Viewing Solutions**
Solutions unlock after completing a challenge:
```
GET /api/solutions/<category>/<level>
```

### **6. Global Scoreboard**
Your progress syncs automatically to the central R00tGlyph server so you can:
- Compete with hackers worldwide
- See your global rank and stats
- Track team progress on the leaderboard

## 🏗️ **Architecture**

```
R00tGlyph/
├── app.py                    # Main Flask application (all routes & logic)
├── run.py                    # Entry point with CLI commands
├── templates/                # Jinja2 templates
│   ├── components/           # Reusable challenge components
│   ├── xss/ sqli/ cmdi/ ...  # Challenge-specific templates
│   ├── admin/                # Admin panel templates
│   └── teams/                # Team management templates
├── static/                   # CSS, JS, uploads
├── data/
│   ├── hints/                # Per-challenge hint JSON files
│   └── solutions/            # Per-challenge solution JSON files
├── instance/                 # SQLite database
└── docker-compose.yml        # Docker deployment
```

## ⚙️ **Command Line Interface**

```bash
python run.py --dev                    # Development server with debug
python run.py --host 0.0.0.0 --port 8080  # Custom host/port
python run.py --reset-db               # Reset database (requires CONFIRM)
python run.py --backup                 # Create database backup
python run.py --restore                # Restore from backup
```

### **Environment Variables**

```bash
# Global Scoreboard (set to empty string to disable sync)
ROOTGLYPH_API_URL=https://api.rootglyph.org  # Central scoreboard server

# Application
SECRET_KEY=your_secret_key_here
FLASK_ENV=development
```

## 🔒 **Security Features**

- **Rate Limiting**: Login (10 req/5min), Flag submission (30 req/min)
- **Password Hashing**: Werkzeug secure password hashing
- **Session Security**: HTTPOnly, Secure, SameSite cookies
- **Input Validation**: All user inputs validated and sanitized
- **CSRF Protection**: Platform itself is protected against CSRF
- **Admin Access Control**: Role-based admin panel access
- **Privacy-First Sync**: Only anonymous progress data (username, score, completed challenges) is sent to the global scoreboard

## 🎯 **Challenge Detection**

Challenges detect successful exploitation through realistic patterns:
- **XSS**: `<script>`, `<img onerror=`, `javascript:`, `eval(`, etc.
- **SQLi**: `'`, `OR 1=1`, `UNION SELECT`, `SLEEP`, `$ne`, etc.
- **CMDi**: `;`, `|`, `&`, `` ` ``, `$()`, etc.
- **SSRF**: Internal IPs, `169.254.169.254`, `gopher://`, etc.
- **XXE**: `<!ENTITY`, `SYSTEM`, `file://`, parameter entities, etc.
- **SSTI**: `{{`, `{%`, `config`, `__class__`, `__mro__`, etc.
- **CSRF**: Missing CSRF tokens, cross-origin state changes, `?csrf_solved=true`, etc.

## 🌐 **Global Scoreboard**

R00tGlyph features a **global scoreboard** that syncs progress across all instances:
- When you complete a challenge, your progress is anonymously sent to the central server
- View your global rank, total flags captured, and category breakdown
- Compete with hackers worldwide without exposing personal data
- Only your username, score, and completed challenge count are synced
- No passwords, emails, or personal information are ever transmitted

## 🤝 **Contributing**

### **Adding New Challenges**
1. Add challenge definition in `app.py` `reset_database()` function
2. Create template in `templates/<category>/<category>_level<N>.html`
3. Add route handler in `app.py`
4. Create hint file in `data/hints/<category>_level<N>.json`
5. Create solution file in `data/solutions/<category>_level<N>.json`

### **Development Workflow**
```bash
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python run.py --dev
```

## ⚠️ **Educational Purpose & Legal Notice**

R00tGlyph v2.0 is designed exclusively for **educational purposes** and **authorized security testing**. Users must:

- ✅ Only use in controlled, authorized environments
- ✅ Respect all applicable laws and regulations
- ✅ Obtain proper permissions before testing
- ✅ Use knowledge responsibly for defensive purposes
- ❌ Never attack systems without explicit authorization
- ❌ Not use for malicious or illegal activities

## 🔌 **Offline Mode**

R00tGlyph works fully offline. The global scoreboard sync is **optional**:
- Set `ROOTGLYPH_API_URL=""` to disable all external communication
- All challenges, hints, and solutions work without internet
- Local scoreboard always shows players on your instance
- Global sync only sends anonymous progress data when enabled

## 📄 **License**

**License**: Educational Use License

**Made By Algorethm team professionals, for security professionals.**

[![GitHub Stars](https://img.shields.io/github/stars/algorethmpwd/R00tGlyph?style=social)](https://github.com/algorethmpwd/R00tGlyph)
