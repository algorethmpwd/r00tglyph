# R00tGlyph v2.0 - Enterprise Web Security Training Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-Educational-orange.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Training-red.svg)](README.md)

R00tGlyph v2.0 is a comprehensive, enterprise-grade web security training platform designed for security professionals, developers, and ethical hackers. Featuring 188 challenges across 9 vulnerability categories, team-based CTF play, admin panel, progressive hints, detailed solutions, Docker sandboxing, and real-time event streams.

---

## 🚀 **Features**

### **🎯 188 Challenges Across 9 Categories**
| Category | Levels | Difficulty Range | Description |
|----------|--------|-----------------|-------------|
| **XSS** | 1-30 | Beginner → Expert | Reflected, DOM, Stored, WAF bypass, CSP bypass, Prototype Pollution, SVG/CDATA, WebAssembly, WebRTC |
| **SQLi** | 1-23 | Beginner → Expert | UNION, Blind, Time-based, WAF bypass, NoSQL, GraphQL, ORM injection |
| **CMDi** | 1-23 | Beginner → Expert | Basic, Filter bypass, Blind, JSON APIs, Docker container escapes |
| **CSRF** | 1-23 | Beginner → Expert | Form, JSON, SameSite bypass, OAuth, WebSocket, GraphQL mutations |
| **SSRF** | 1-23 | Beginner → Expert | Internal scanning, Cloud metadata (169.254.169.254), DNS rebinding, Protocol smuggling |
| **XXE** | 1-23 | Beginner → Expert | File disclosure, Blind, Billion Laughs, SOAP, OOB data retrieval |
| **SSTI** | 1-23 | Beginner → Expert | Jinja2, Twig, Freemarker, Sandbox escape, RCE |
| **Deserialization** | 1-10 | Beginner → Expert | Python pickle, PHP serialize, Java, .NET, YAML deserialization |
| **Auth Bypass** | 1-10 | Beginner → Expert | SQLi login, JWT manipulation, Session fixation, OAuth, MFA bypass |

### **🏗️ Platform Features & Recent Upgrades**
- **Dynamic Challenge Engine** - Modular evaluation engine in `app/engine/sinks.py` processing all 9 vulnerability categories.
- **Docker Container Sandboxing** - Isolated, read-only container execution (`alpine:latest --network none`) for realistic CMDi payload evaluation.
- **Out-of-Band (OOB) Callback Listener** - Dedicated `/api/oob/<token>` endpoint for OOB XXE, SSRF, and SQLi exfiltration testing.
- **Real-Time CTF Activity Stream** - Server-Sent Events (SSE) `/api/activity/stream` endpoint pushing live flag captures.
- **Redis & Distributed Rate Limiting** - Seamless Redis integration via `REDIS_URL` with automatic in-memory fallback.
- **Global & Team Scoreboard** - Individual rank tracking and team CTF competition leaderboard (optimized via SQL joins).
- **Progressive Hint & Solution System** - Contextual hints and step-by-step walkthroughs unlocked per challenge level.
- **Admin Control Panel** - Dashboard analytics, user management, and instant challenge activation toggles.
- **Unique Flag Isolation** - Dynamically hashed per-user flags (`R00T{md5_hash}`).

---

## 📦 **Installation & Deployment**

### **🔧 Quick Start (Local Development)**

```bash
# 1. Clone repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# 2. Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start development server
python run.py --dev
```

Access the platform at: **`http://localhost:5000`**

### **🐳 Docker Deployment**

```bash
# Start container stack
docker-compose up -d

# Development mode with Adminer
docker-compose --profile development up -d

# Production mode with PostgreSQL
docker-compose --profile production up -d
```

---

## 🏗️ **Architecture & Modular Directory Structure**

```
R00tGlyph/
├── run.py                    # Entry point with CLI commands (--dev, --reset-db, --backup, --restore)
├── app/                      # Application Factory package
│   ├── __init__.py           # Flask app factory, extension init, and blueprint registrations
│   ├── models.py             # SQLAlchemy models (LocalUser, Challenge, Flag, Team, Submission)
│   ├── extensions.py         # SQLAlchemy & RateLimiter (Redis + In-Memory fallback)
│   ├── utils.py              # Auth helpers, Docker sandbox (safe_execute_command), flag generator
│   ├── reset_db_func.py      # Seed script populating all 188 challenges
│   ├── engine/
│   │   └── sinks.py          # Vulnerability evaluation sinks (XSS, SQLi, CMDi, XXE, SSTI, etc.)
│   └── routes/
│       ├── auth.py           # Registration, login, logout, account lockout
│       ├── core.py           # Profile, challenge catalog, scoreboard, team scoreboard
│       ├── api.py            # Flag submission, hints, solutions, OOB listener, SSE activity stream
│       ├── challenge_router.py # Dynamic route dispatcher (/<category>/level<N>)
│       ├── admin.py          # Admin analytics panel & user/challenge controls
│       └── teams.py          # Team creation, joining, and member stats
├── data/
│   ├── challenges/           # Per-challenge YAML configuration files
│   ├── hints/                # Per-challenge hint JSON files
│   └── solutions/            # Per-challenge solution walkthrough JSON files
├── templates/                # Jinja2 HTML templates
├── static/                   # CSS themes (Dark, Light, Cyberpunk, Hacker), JS scripts
├── instance/                 # SQLite database storage (r00tglyph.db)
└── docker-compose.yml        # Docker deployment configuration
```

---

## ⚙️ **Command Line Interface & Environment Variables**

```bash
python run.py --dev                    # Run in development mode with debug & auto-reload
python run.py --host 0.0.0.0 --port 8080  # Run on all network interfaces
python run.py --reset-db               # Reset database & seed challenges (requires 'CONFIRM')
python run.py --backup                 # Create timestamped database backup
python run.py --restore                # Restore database from latest backup
```

### **Environment Variables (`.env`)**

```bash
# Application Configuration
SECRET_KEY=your_secure_secret_key_here
FLASK_ENV=development

# Database (SQLite default, PostgreSQL for production)
DATABASE_URL=sqlite:///instance/r00tglyph.db
# DATABASE_URL=postgresql://rootglyph:password@localhost:5432/rootglyph

# Optional Distributed Rate Limiting
REDIS_URL=redis://localhost:6379/0

# Global Scoreboard (optional central sync)
ROOTGLYPH_API_URL=https://api.rootglyph.org
```

---

## 🔒 **Security Features**

- **Rate Limiting**: Login (10 req/5min), Flag submission (30 req/min) with Redis persistence support.
- **Account Lockout**: 5 failed login attempts trigger a 15-minute account lockout.
- **Password Security**: Werkzeug secure password hashing (PBKDF2/SHA256).
- **Session Protection**: HTTPOnly, Secure, SameSite cookies.
- **CSRF Protection**: Global CSRF protection with selective exemptions for test payload sinks.
- **User Flag Isolation**: MD5 per-user flag derivation prevents flag sharing.

---

## 🎯 **API Endpoints**

- `POST /submit-flag` - Validates user flag submission and awards points.
- `GET /api/hints/<category>/<level>` - Returns hint JSON data.
- `GET /api/solutions/<category>/<level>` - Returns solution JSON data (unlocked upon challenge completion).
- `GET / POST /api/oob/<token>` - Out-of-band listener for OOB payload callbacks.
- `GET /api/activity/stream` - Server-Sent Events (SSE) streaming real-time CTF capture events.

---

## ⚠️ **Educational Purpose & Legal Notice**

R00tGlyph v2.0 is designed exclusively for **educational purposes** and **authorized security testing**.

- ✅ Only use in controlled, authorized environments
- ✅ Respect all applicable laws and regulations
- ❌ Never attack systems without explicit authorization

---

## 📄 **License**

**License**: Educational Use License

**Made by security professionals, for security professionals.**
