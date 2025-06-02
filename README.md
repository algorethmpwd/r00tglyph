# R00tGlyph - Advanced Web Security Training Platform

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-Educational-orange.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Local-red.svg)](README.md)

R00tGlyph is a comprehensive web security training platform designed to help security professionals, developers, and ethical hackers learn and practice various web application vulnerabilities in a controlled environment. All challenges are based on current 2024-2025 vulnerability trends and real-world scenarios.

## 🚀 Features

- **115 Comprehensive Challenges**: 23 levels each for XSS, SQL Injection, Command Injection, CSRF, and SSRF
- **Modern Vulnerability Contexts**: Challenges simulate real-world applications (fintech, healthcare, e-commerce, cloud platforms)
- **Tool Integration**: Levels require use of industry-standard tools (Burp Suite, SQLMap, Nmap, etc.)
- **Progressive Difficulty**: From beginner to expert level challenges
- **User Progress Tracking**: Track your progress and achievements across all categories
- **Flag-based Challenges**: Each challenge has a unique flag to capture
- **Multiple UI Themes**: Dark, Cyberpunk, Hacker, and Light themes with full responsive design
- **Machine-based Authentication**: No passwords required - uses unique machine identification
- **Automatic Updates**: Git-based update mechanism preserves user progress while pulling latest challenges
- **Comprehensive Backup System**: Automated and manual backup/restore functionality

## 🎯 Challenge Categories

### 🔥 Cross-Site Scripting (XSS) - 23 Levels
Modern web application XSS vulnerabilities covering:
- **Levels 1-3**: Basic reflected, DOM-based, and stored XSS in modern frameworks
- **Levels 4-6**: Filter bypass techniques in enterprise applications
- **Levels 7-9**: Advanced techniques (HTTP headers, JSON APIs, CSP bypass)
- **Levels 10-15**: Expert techniques (mutation observers, SVG, blind XSS, PDF generation, prototype pollution, template injection)
- **Levels 16-23**: Cutting-edge contexts (WebAssembly, PWAs, Web Components, GraphQL, WebRTC, Web APIs, WebGPU, federated identity)

### 💉 SQL Injection (SQLi) - 23 Levels
Modern database injection vulnerabilities covering:
- **Levels 1-4**: Basic injection, search, UNION, and blind techniques
- **Levels 5-8**: Advanced techniques (time-based, WAF bypass, second-order, JSON parameters)
- **Levels 9-15**: Expert techniques with tools (SQLMap, stored procedures, ORM, XML, Burp Suite, column names, ORDER BY, error-based)
- **Levels 16-23**: Modern contexts (LIMIT clause, boolean-based blind, subqueries, out-of-band, GraphQL, NoSQL, cloud databases)

### ⚡ Command Injection (CMDi) - 23 Levels
Modern system command injection vulnerabilities covering:
- **Levels 1-4**: Basic injection, filters, blind techniques, file upload chaining
- **Levels 5-8**: Advanced techniques (API parameters, WAF bypass, time-based, Burp Suite integration)
- **Levels 9-15**: Expert techniques (JSON APIs, environment variables, XML processing, Nmap integration, GraphQL, WebSockets, serverless)
- **Levels 16-23**: Modern contexts (process substitution, containers, template engines, message queues, out-of-band, cloud functions, SSH, advanced chaining)

### 🔄 Cross-Site Request Forgery (CSRF) - 23 Levels
Modern CSRF attack techniques covering:
- **Levels 1-4**: Basic CSRF, GET requests, POST requests, hidden form fields
- **Levels 5-8**: Advanced bypass techniques (referer header, custom headers, AJAX, JSON payloads)
- **Levels 9-15**: Expert techniques (file upload, multi-step processes, password change, CAPTCHA bypass, CORS exploitation, WebSocket, OAuth flows)
- **Levels 16-23**: Modern contexts (CSP bypass, XSS chaining, GraphQL, JWT-based, mobile APIs, microservices, subdomain takeover, serverless)

### 🌐 Server-Side Request Forgery (SSRF) - 23 Levels
Modern SSRF attack techniques covering:
- **Levels 1-4**: Basic SSRF, internal network access, port scanning, protocol smuggling
- **Levels 5-8**: Advanced techniques (filter bypass, DNS rebinding, cloud metadata, blind exploitation)
- **Levels 9-15**: Expert techniques (file protocol, gopher protocol, Redis, Docker API, Kubernetes API, time-based detection, HTTP smuggling)
- **Levels 16-23**: Modern contexts (WebSocket upgrade, GraphQL introspection, LDAP injection, XXE chaining, cloud functions, database access, message queues, advanced chaining)

## 🛠️ Tools Integration

R00tGlyph challenges are designed to work with real bug bounty and penetration testing tools:
- **Burp Suite**: Web application security testing and proxy
- **SQLMap**: Automated SQL injection detection and exploitation
- **Nmap**: Network discovery and security auditing
- **Nuclei**: Fast vulnerability scanner
- **FFUF**: Fast web fuzzer
- **Gobuster**: Directory/file enumeration tool
- **Sublist3r**: Subdomain enumeration
- **Waybackurls**: Historical URL discovery

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- Git (for updates and cloning)
- Modern web browser (Chrome, Firefox, Safari, Edge)

---

## 🖥️ Platform-Specific Installation

### 🪟 Windows Installation

#### Method 1: Using Command Prompt
```cmd
# Clone the repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Create virtual environment (recommended)
python -m venv r00tglyph-env
r00tglyph-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

#### Method 2: Using PowerShell
```powershell
# Clone the repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
Set-Location R00tGlyph

# Create virtual environment
python -m venv r00tglyph-env
.\r00tglyph-env\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

#### Windows Prerequisites Installation
```cmd
# Install Python (if not installed)
# Download from: https://www.python.org/downloads/windows/

# Install Git (if not installed)
# Download from: https://git-scm.com/download/win

# Verify installations
python --version
git --version
```

---

### 🍎 macOS Installation

#### Method 1: Using Terminal
```bash
# Clone the repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Create virtual environment (recommended)
python3 -m venv r00tglyph-env
source r00tglyph-env/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Run the application
python3 app.py
```

#### Method 2: Using Homebrew
```bash
# Install Python and Git via Homebrew (if not installed)
brew install python git

# Clone and setup
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Create virtual environment
python3 -m venv r00tglyph-env
source r00tglyph-env/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Run the application
python3 app.py
```

#### macOS Prerequisites Installation
```bash
# Install Xcode Command Line Tools (includes Git)
xcode-select --install

# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python via Homebrew
brew install python

# Verify installations
python3 --version
git --version
```

---

### 🐧 Linux Installation

#### Ubuntu/Debian-based Systems
```bash
# Update package list
sudo apt update

# Install Python, pip, and Git
sudo apt install python3 python3-pip python3-venv git -y

# Clone the repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Create virtual environment
python3 -m venv r00tglyph-env
source r00tglyph-env/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Run the application
python3 app.py
```

#### CentOS/RHEL/Fedora Systems
```bash
# For CentOS/RHEL 7/8
sudo yum install python3 python3-pip git -y

# For Fedora/RHEL 9+
sudo dnf install python3 python3-pip git -y

# Clone the repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Create virtual environment
python3 -m venv r00tglyph-env
source r00tglyph-env/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Run the application
python3 app.py
```

#### Arch Linux
```bash
# Install Python, pip, and Git
sudo pacman -S python python-pip git

# Clone the repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Create virtual environment
python -m venv r00tglyph-env
source r00tglyph-env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

#### openSUSE
```bash
# Install Python, pip, and Git
sudo zypper install python3 python3-pip git

# Clone the repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Create virtual environment
python3 -m venv r00tglyph-env
source r00tglyph-env/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Run the application
python3 app.py
```

---

### 🐳 Docker Installation (All Platforms)

#### Using Docker
```bash
# Clone the repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Build Docker image
docker build -t r00tglyph .

# Run container
docker run -p 5000:5000 r00tglyph

# Access the application at http://localhost:5000
```

#### Docker Compose
```bash
# Clone the repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Run with Docker Compose
docker-compose up -d

# Access the application at http://localhost:5000
```

---

### 📱 Termux (Android)

```bash
# Update packages
pkg update && pkg upgrade

# Install Python and Git
pkg install python git

# Clone the repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

---

### 🔧 Post-Installation Setup

#### Access the Application
After successful installation, open your web browser and navigate to:
```
http://localhost:5000
```

#### Verify Installation
```bash
# Check if the application is running
curl http://localhost:5000

# Or check the process
ps aux | grep python
```

#### Troubleshooting Common Issues

**Port Already in Use:**
```bash
# Find process using port 5000
lsof -i :5000  # macOS/Linux
netstat -ano | findstr :5000  # Windows

# Kill the process or use different port
python app.py --port 5001
```

**Permission Issues (Linux/macOS):**
```bash
# Fix permissions
chmod +x app.py
sudo chown -R $USER:$USER R00tGlyph/
```

**Python Version Issues:**
```bash
# Check Python version
python --version
python3 --version

# Use specific Python version
python3.9 app.py
```

## ⚙️ Command Line Interface

The application supports several command-line arguments for maintenance and management:

```bash
python app.py -h                # Show help menu with all available options
python app.py --update          # Update R00tGlyph to the latest version
python app.py --backup          # Create manual backup of user data
python app.py --restore         # Restore user data from backup
python app.py --reset           # Reset database to initial state (⚠️ LOSES ALL PROGRESS)
```

## 📋 System Requirements

### Minimum Requirements
- **Python**: 3.7 or higher
- **RAM**: 512MB available memory
- **Storage**: 100MB free disk space
- **Network**: Internet connection (for updates and tool downloads)

### Dependencies
- **Flask**: 2.3.3 - Web framework
- **Flask-SQLAlchemy**: 3.1.1 - Database ORM
- **Werkzeug**: 2.3.7 - WSGI utilities

### Supported Platforms
- ✅ Windows 10/11
- ✅ macOS 10.14+
- ✅ Linux (Ubuntu 18.04+, CentOS 7+, Debian 9+)

## ⚠️ Educational Purpose & Legal Notice

**IMPORTANT**: This platform is designed **exclusively for educational purposes**.

- ✅ **Authorized Use**: Learning web security concepts and techniques
- ✅ **Permitted**: Testing on your own systems or with explicit permission
- ❌ **Prohibited**: Using skills learned here on systems without authorization
- ❌ **Illegal**: Unauthorized access to computer systems or networks

**By using R00tGlyph, you agree to use the knowledge gained responsibly and ethically.**

## 🔄 Update Mechanism

R00tGlyph includes a robust Git-based update system that preserves user progress:

```bash
python app.py --update
```

### Update Process
1. **🔒 Automatic Backup**: Creates timestamped backup of your progress
2. **📥 Pull Latest Code**: Downloads latest challenges and features from GitHub
3. **💾 Preserve Progress**: Restores your user data and completed challenges
4. **🗄️ Update Database**: Adds new challenges while keeping existing progress
5. **🛡️ Safe Rollback**: Your data remains backed up if anything goes wrong

### Data Management Commands
```bash
python app.py --backup          # Create manual backup of user data
python app.py --restore         # Restore from most recent backup
python app.py --reset           # ⚠️ Reset database (LOSES ALL PROGRESS)
```

### Backup Location
- Backups are stored in the `backup/` directory
- Timestamped format: `r00tglyph_YYYYMMDD_HHMMSS.db.bak`
- Pre-restore backups are automatically created for safety

## 🚀 Upcoming Features

### New Vulnerability Categories (Planned)
- **XXE Injection**: XML External Entity vulnerabilities (23 levels)
- **SSTI**: Server-Side Template Injection (23 levels)
- **Deserialization**: Insecure deserialization attacks (23 levels)
- **File Inclusion**: LFI/RFI vulnerabilities (23 levels)
- **Business Logic**: Logic flaw exploitation (23 levels)
- **Authentication Bypass**: Auth mechanism weaknesses (23 levels)

### Platform Improvements (In Development)
- **Multi-user Support**: Team-based learning and competitions
- **Progress Analytics**: Detailed learning insights and statistics
- **Hint System**: Progressive hints for challenging levels
- **Achievement System**: Badges and milestones for motivation
- **Export/Import**: Progress backup and transfer between machines
- **API Integration**: RESTful API for external tool integration

## 👤 User Progress & Challenge Management

### Progress Tracking System
- **Sequential Numbering**: Challenges numbered for easy navigation
- **Automatic Completion**: Challenges marked complete upon flag submission
- **Comprehensive Profile**: View all completed and remaining challenges
- **Username Persistence**: Changes propagate throughout the application
- **Accurate Statistics**: Real-time tracking of completion rates
- **Flag Security**: Unique flags revealed only upon successful completion

### Challenge Features
- **Popup Descriptions**: Detailed challenge descriptions in modal windows
- **Solution Pages**: Comprehensive explanations for every challenge
- **Progress Preservation**: Updates maintain all user progress and achievements
- **Difficulty Progression**: Clear path from beginner to expert levels

## 🏗️ Architecture & Technical Details

### Application Structure
```
R00tGlyph/
├── app.py                 # Main Flask application (8,662 lines)
├── update_db.py          # Database initialization and management
├── requirements.txt      # Python dependencies
├── templates/            # HTML templates organized by category
│   ├── xss/             # XSS challenge templates (23 levels)
│   ├── sqli/            # SQL injection templates (23 levels)
│   ├── cmdi/            # Command injection templates (23 levels)
│   ├── csrf/            # CSRF templates (23 levels)
│   ├── ssrf/            # SSRF templates (23 levels)
│   └── solutions/       # Solution pages for all challenges
├── static/              # CSS, JavaScript, and assets
│   ├── css/style.css    # Theme system and responsive design
│   └── js/main.js       # Client-side functionality
├── instance/            # SQLite database storage
└── backup/              # Automated backup storage
```

### Database Schema
- **LocalUser**: Machine-based user identification and progress tracking
- **Challenge**: Challenge metadata (115 total challenges)
- **Flag**: Unique flag generation per user/challenge combination
- **Submission**: Complete audit trail of all flag attempts
- **Comment**: User-generated content for stored XSS challenges

### Technology Stack
- **Backend**: Flask 2.3.3 with SQLAlchemy ORM
- **Database**: SQLite (local file-based)
- **Frontend**: Bootstrap 5 with responsive design
- **Authentication**: Machine ID-based (no passwords)
- **Themes**: CSS custom properties (Dark, Cyberpunk, Hacker, Light)

## 🐛 Known Issues & Limitations

### Current Limitations
- **Single-file Architecture**: Main application is 8,662 lines (needs modularization)
- **SQLite Constraints**: No concurrent write access, limited scalability
- **JSON Data Storage**: Progress stored as JSON strings (affects querying)
- **No Testing Framework**: No automated tests or CI/CD pipeline
- **Basic Authentication**: Machine ID-based system has transfer limitations

### Security Considerations
- **Educational Use Only**: Not hardened for production deployment
- **Local Deployment**: Designed for single-user local installation
- **Default Secret Key**: Should be changed for any shared deployment
- **Input Validation**: Limited validation on user inputs (by design for challenges)

## 📞 Support & Community

### Getting Help
- **GitHub Issues**: [Report bugs or request features](https://github.com/algorethmpwd/R00tGlyph/issues)
- **Documentation**: Check this README and inline code comments
- **Community**: Join discussions on GitHub Discussions

### Contributing
- **Bug Reports**: Use GitHub Issues with detailed reproduction steps
- **Feature Requests**: Propose new challenges or platform improvements
- **Code Contributions**: Fork, develop, and submit pull requests
- **Challenge Ideas**: Suggest new vulnerability scenarios

## 📜 Repository & Links

- **🔗 GitHub Repository**: https://github.com/algorethmpwd/R00tGlyph
- **📺 Creator's YouTube**: [Algorethm](https://youtube.com/@algorethm_)
- **💬 Telegram**: [Contact](https://t.me/hackerpwd1)
- **💝 Support**: [PayPal Donation](https://www.paypal.com/donate/?hosted_button_id=Z9HENP8G6PTD6)

## 📄 License & Credits

**Created by**: [Algorethm](https://youtube.com/@algorethm_)

**License**: Educational Use Only - See repository for full terms

**Acknowledgments**:
- Flask and SQLAlchemy communities
- Bootstrap team for responsive framework
- Security research community for vulnerability insights
- All contributors and users providing feedback

---

**⚠️ Disclaimer**: R00tGlyph is an educational platform. Users are responsible for ethical and legal use of knowledge gained. The creators are not liable for misuse of techniques learned through this platform.
