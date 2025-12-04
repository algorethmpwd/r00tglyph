# R00tGlyph v2.0 - Enterprise Web Security Training Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-Educational-orange.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Training-red.svg)](README.md)

R00tGlyph v2.0 is a comprehensive, enterprise-grade web security training platform designed for security professionals, developers, and ethical hackers. Featuring a completely rewritten architecture with microservices support, advanced analytics, and professional-grade infrastructure.

## 🚀 **What's New in v2.0**

### **🏗️ Enterprise Architecture**
- **Microservices Design**: Modular, scalable architecture with proper separation of concerns
- **Professional MVC Structure**: Clean code organization following industry best practices
- **Docker-First Deployment**: Full containerization with production-ready compose files
- **Comprehensive Monitoring**: Prometheus, Grafana, ELK stack integration

### **📊 Advanced Analytics & Intelligence**
- **Real-time User Analytics**: Learning velocity, performance trends, skill gap analysis
- **Challenge Difficulty AI**: Dynamic difficulty scoring based on completion metrics
- **Behavioral Insights**: Activity patterns, peak performance times, learning preferences
- **Security Event Monitoring**: Threat detection, payload analysis, anomaly detection

### **🎓 Enhanced Learning Experience**
- **Level-Specific Hints**: Contextual, progressive hints for each individual challenge
- **Detailed Solutions**: Step-by-step walkthroughs with technical analysis
- **Learning Paths**: Structured curricula for guided skill development
- **Achievement System**: Dynamic unlocks based on progress and performance

### **🔧 Professional Infrastructure**
- **Redis Caching**: High-performance caching and session management
- **PostgreSQL**: Enterprise database with proper normalization
- **Rate Limiting**: Anti-abuse protection with sophisticated controls
- **SSL/TLS Support**: Production-ready security configurations

## 🎯 **Challenge Categories**

### **🔥 Cross-Site Scripting (XSS) - 23 Levels**
Progressive XSS training covering:
- **Beginner (1-5)**: Basic reflected, DOM, stored XSS
- **Intermediate (6-10)**: Filter bypass, WAF evasion, JSON contexts
- **Advanced (11-17)**: SVG XSS, blind XSS, CSP bypass, prototype pollution
- **Expert (18-23)**: WebAssembly, PWAs, GraphQL, federated identity systems

### **💉 SQL Injection (SQLi) - 23 Levels**  
Comprehensive database injection training:
- **Beginner (1-5)**: Basic injection, UNION attacks, blind techniques
- **Intermediate (6-10)**: Time-based, WAF bypass, second-order injection
- **Advanced (11-17)**: ORM exploitation, stored procedures, XML injection
- **Expert (18-23)**: NoSQL, GraphQL, cloud databases, advanced chaining

### **⚡ Command Injection (CMDi) - 23 Levels**
System-level exploitation techniques:
- **Beginner (1-5)**: Basic command injection, filter evasion
- **Intermediate (6-10)**: Blind techniques, API parameter injection
- **Advanced (11-17)**: Container escapes, environment manipulation
- **Expert (18-23)**: Serverless functions, cloud metadata, advanced chaining

### **🔄 Cross-Site Request Forgery (CSRF) - 23 Levels**
Modern CSRF attack vectors:
- **Beginner (1-5)**: Basic CSRF, token manipulation
- **Intermediate (6-10)**: AJAX bypass, JSON payloads, custom headers
- **Advanced (11-17)**: Multi-step processes, WebSocket exploitation
- **Expert (18-23)**: GraphQL mutations, microservices, OAuth flows

### **🌐 Server-Side Request Forgery (SSRF) - 23 Levels**
Internal network exploitation:
- **Beginner (1-5)**: Basic SSRF, internal network discovery
- **Intermediate (6-10)**: Filter bypass, DNS rebinding, cloud metadata
- **Advanced (11-17)**: Protocol smuggling, Docker API, Kubernetes exploitation
- **Expert (18-23)**: Advanced chaining, message queues, serverless contexts

## 🛠️ **Professional Tool Integration**

R00tGlyph v2.0 is designed for real-world security testing workflows:

- **Burp Suite Professional**: Advanced web application security testing
- **SQLMap**: Automated SQL injection detection and exploitation  
- **Nmap**: Network discovery and security auditing
- **Nuclei**: Fast vulnerability scanner with custom templates
- **FFUF**: High-performance web fuzzer
- **Gobuster**: Directory and file enumeration
- **Custom Tools**: Built-in payload generators and analysis utilities

## 📦 **Installation & Deployment**

### **🐳 Production Deployment (Recommended)**

**Quick Start with Docker:**
```bash
# Clone repository
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph

# Start full stack
docker-compose up -d

# Access application
open http://localhost
```

**Advanced Production Setup:**
```bash
# Full monitoring stack
docker-compose --profile production up -d

# Access services
# Main App: http://localhost
# Grafana: http://localhost:3000
# Prometheus: http://localhost:9090
# Kibana: http://localhost:5601
```

### **🔧 Development Setup**

**Local Development:**
```bash
# Clone and setup virtual environment
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python run.py --init-db

# Start development server
python run.py --dev
```

**Development with Docker:**
```bash
# Start development environment
docker-compose --profile development up -d

# Access development tools
# Adminer: http://localhost:8080
# MailHog: http://localhost:8025
```

### **☸️ Kubernetes Deployment**

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/rootglyph.yaml
kubectl apply -f k8s/ingress.yaml
```

## 🎮 **Getting Started**

### **1. First Launch**
```bash
# Initialize the platform
python run.py --init-db

# Check system health
python run.py --check-health

# Start the server
python run.py
```

### **2. Access the Platform**
- **Main Interface**: http://localhost:5000
- **Create Account**: Click "Register" and create your profile
- **Start Learning**: Begin with XSS Level 1 or follow a learning path

### **3. Challenge Workflow**
1. **Select Challenge**: Choose from 115+ available challenges
2. **Read Scenario**: Understand the vulnerable application context
3. **Analyze Code**: Use developer tools to identify vulnerabilities
4. **Craft Payload**: Develop and test your exploit
5. **Submit Flag**: Capture the flag to complete the challenge
6. **Review Solution**: Study the detailed walkthrough and prevention methods

## 🎓 **Learning Features**

### **📚 Progressive Hint System**
Each challenge includes contextual hints that unlock based on your attempts:
- **Concept Hints**: Understanding the vulnerability type
- **Technical Hints**: Specific exploitation techniques
- **Tool Hints**: Recommended tools and usage
- **Solution Hints**: Step-by-step guidance (with point penalty)

### **📖 Comprehensive Solutions**
Post-completion access to detailed solutions including:
- **Step-by-step walkthroughs**
- **Technical vulnerability analysis** 
- **Prevention and mitigation strategies**
- **Real-world attack scenarios**
- **Code examples and patches**

### **🛤️ Learning Paths**
Structured curricula for different skill levels:
- **Web Security Fundamentals**: Core concepts and basic attacks
- **OWASP Top 10 Mastery**: Complete coverage of critical web vulnerabilities
- **Advanced Exploitation**: Complex attack chains and modern techniques
- **Bug Bounty Preparation**: Real-world hunting methodologies

### **🏆 Achievement System**
Dynamic achievements that unlock based on your progress:
- **Completion Badges**: Category and difficulty milestones
- **Speed Achievements**: Fast completion rewards
- **Streak Rewards**: Consistent learning recognition
- **Perfect Scores**: No-hint completion bonuses

## 📊 **Analytics Dashboard**

### **📈 Personal Analytics**
- **Learning Velocity**: Challenges completed over time
- **Performance Trends**: Success rates and improvement curves  
- **Category Strengths**: Skill assessment across vulnerability types
- **Activity Patterns**: Peak performance times and study habits

### **🎯 Challenge Intelligence**
- **Difficulty Scoring**: AI-powered difficulty assessment
- **Success Metrics**: Community completion rates and average times
- **Popular Techniques**: Most effective exploitation methods
- **Learning Recommendations**: Personalized next challenges

### **🔍 Security Monitoring**
- **Attack Pattern Analysis**: Payload effectiveness tracking
- **Anomaly Detection**: Unusual behavior identification
- **Threat Intelligence**: Attack trend analysis
- **Performance Optimization**: Platform usage insights

## ⚙️ **Command Line Interface**

R00tGlyph v2.0 includes a comprehensive CLI for management:

```bash
# Server Management
python run.py --dev                    # Development server
python run.py --host 0.0.0.0 --port 8080  # Custom host/port

# Database Operations  
python run.py --init-db               # Initialize fresh database
python run.py --reset-db              # Reset all data (requires confirmation)
python run.py --migrate               # Run database migrations

# Backup & Recovery
python run.py --backup                # Create data backup
python run.py --restore               # Restore latest backup
python run.py --list-backups          # Show available backups

# System Maintenance
python run.py --update                # Update to latest version
python run.py --check-health          # System health check
python run.py --version               # Version information
```

## 🏗️ **System Architecture**

### **📁 Project Structure**
```
R00tGlyph/
├── app/                          # Main application package
│   ├── controllers/              # Route handlers and business logic
│   │   ├── challenges/           # Challenge-specific controllers
│   │   │   ├── xss.py           # XSS challenge implementations
│   │   │   ├── sqli.py          # SQL injection challenges
│   │   │   └── base_challenge.py # Base challenge controller
│   │   ├── auth.py              # Authentication routes
│   │   ├── main.py              # Main application routes
│   │   └── api.py               # REST API endpoints
│   ├── models/                   # Database models
│   │   ├── __init__.py          # Model definitions
│   │   ├── user.py              # User and team models
│   │   └── challenge.py         # Challenge and progress models
│   ├── services/                 # Business logic services
│   │   ├── analytics_service.py # Analytics and reporting
│   │   ├── flag_service.py      # Flag generation and validation
│   │   ├── progress_service.py  # User progress tracking
│   │   └── backup_service.py    # Backup and recovery
│   └── utils/                    # Utility functions
├── data/                         # Challenge data and content
│   ├── challenges/              # Challenge definitions
│   ├── hints/                   # Level-specific hints
│   └── solutions/               # Detailed solutions
├── docker/                       # Docker configuration
├── templates/                    # Jinja2 templates
├── static/                       # Static assets
└── tests/                        # Test suite
```

### **🔧 Technology Stack**
- **Backend**: Flask 2.3.3, SQLAlchemy, Redis
- **Database**: PostgreSQL (production), SQLite (development)
- **Caching**: Redis with intelligent caching strategies
- **Frontend**: Bootstrap 5.3, Custom CSS themes, Real-time updates
- **Monitoring**: Prometheus, Grafana, ELK Stack
- **Container**: Docker, Docker Compose, Kubernetes ready

## 🔒 **Security Features**

### **🛡️ Application Security**
- **Rate Limiting**: Intelligent request throttling
- **Input Validation**: Comprehensive sanitization
- **CSRF Protection**: Token-based request validation
- **Content Security Policy**: XSS prevention headers
- **Secure Sessions**: HTTPOnly, Secure, SameSite cookies

### **🔐 Authentication & Authorization**
- **Bcrypt Hashing**: Secure password storage
- **Session Management**: Secure session handling
- **Role-based Access**: User, instructor, admin roles
- **Account Lockout**: Brute force protection

### **📋 Compliance & Monitoring**
- **Audit Logging**: Comprehensive activity logs
- **Security Events**: Real-time threat detection
- **Data Privacy**: GDPR-compliant data handling
- **Backup Encryption**: Secure backup storage

## 🌐 **Deployment Options**

### **☁️ Cloud Platforms**
- **Render**: One-click deployment with database
- **Heroku**: Container registry deployment
- **AWS**: ECS, EKS, or EC2 deployment options
- **Google Cloud**: GKE or Compute Engine deployment
- **Azure**: Container Instances or AKS deployment

### **🖥️ On-Premises**
- **Docker Compose**: Full-stack local deployment
- **Kubernetes**: Enterprise container orchestration  
- **Bare Metal**: Traditional server installation
- **VM Deployment**: Virtual machine setup

### **🔧 Configuration Management**
- **Environment Variables**: Secure configuration
- **Docker Secrets**: Container secret management
- **ConfigMaps**: Kubernetes configuration
- **SSL/TLS**: Automated certificate management

## 📈 **Performance & Scaling**

### **⚡ Performance Optimizations**
- **Redis Caching**: Sub-millisecond response times
- **Database Indexing**: Optimized query performance
- **Static Asset CDN**: Fast content delivery
- **Gzip Compression**: Reduced bandwidth usage

### **📊 Scalability Features**
- **Horizontal Scaling**: Multi-instance deployment
- **Load Balancing**: Nginx reverse proxy
- **Database Replication**: Read replica support
- **Microservices Ready**: Service decomposition support

## 🧪 **Testing & Quality Assurance**

### **🔍 Test Suite**
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test categories
pytest tests/unit/          # Unit tests
pytest tests/integration/   # Integration tests
pytest tests/security/      # Security tests
```

### **🛠️ Development Tools**
- **Code Formatting**: Black, isort
- **Linting**: Flake8, mypy
- **Security Scanning**: Bandit, safety
- **Performance Profiling**: py-spy, memory-profiler

## 🤝 **Contributing & Development**

### **🔄 Development Workflow**
```bash
# Setup development environment
git clone https://github.com/algorethmpwd/R00tGlyph.git
cd R00tGlyph
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

# Run development server with hot reload
python run.py --dev

# Run tests before committing
pytest
black .
flake8 .
```

### **📝 Adding New Challenges**
1. Create challenge template in `templates/[category]/`
2. Add challenge data in `data/challenges/`
3. Create level-specific hints in `data/hints/`
4. Write detailed solution in `data/solutions/`
5. Implement controller logic in `app/controllers/challenges/`
6. Add database migration if needed
7. Write tests for new functionality

## 🔧 **Troubleshooting**

### **🚨 Common Issues**

**Database Connection Issues:**
```bash
# Check database status
python run.py --check-health

# Reset database if corrupted
python run.py --reset-db

# Check PostgreSQL logs
docker-compose logs postgres
```

**Redis Connection Problems:**
```bash
# Test Redis connectivity
redis-cli ping

# Restart Redis service
docker-compose restart redis

# Clear Redis cache
redis-cli flushall
```

**Performance Issues:**
```bash
# Monitor resource usage
docker-compose logs --tail=100

# Check system resources
python run.py --check-health

# Profile application performance
py-spy top --pid $(pgrep -f "python run.py")
```

## 📞 **Support & Community**

### **🆘 Getting Help**
- **GitHub Issues**: Bug reports and feature requests
- **Documentation**: Comprehensive guides and tutorials
- **Community Discord**: Real-time support and discussions
- **Email Support**: security-training@rootglyph.org

### **🤝 Contributing**
- **Bug Reports**: Detailed issue descriptions
- **Feature Requests**: Enhancement proposals
- **Code Contributions**: Pull requests welcome
- **Documentation**: Help improve guides and tutorials

### **📚 Resources**
- **Official Documentation**: https://docs.rootglyph.org
- **Video Tutorials**: https://youtube.com/rootglyph
- **Blog Posts**: https://blog.rootglyph.org
- **Security Research**: https://research.rootglyph.org

## ⚠️ **Educational Purpose & Legal Notice**

R00tGlyph v2.0 is designed exclusively for **educational purposes** and **authorized security testing**. Users must:

- ✅ Only use in controlled, authorized environments
- ✅ Respect all applicable laws and regulations
- ✅ Obtain proper permissions before testing
- ✅ Use knowledge responsibly for defensive purposes
- ❌ Never attack systems without explicit authorization
- ❌ Not use for malicious or illegal activities

## 📄 **License & Credits**

**License**: Educational Use License - See [LICENSE](LICENSE) file for details

**Credits**:
- **Core Team**: Security researchers and developers
- **Community**: Contributors and security professionals
- **Inspiration**: OWASP, PortSwigger, real-world vulnerabilities
- **Tools**: Built with love using Flask, PostgreSQL, Redis, and Docker

**Acknowledgments**: Special thanks to the cybersecurity community for continuous feedback and contributions.

---

**Made with ❤️ by security professionals, for security professionals.**

**Start your advanced web security journey today!** 🚀

[![GitHub Stars](https://img.shields.io/github/stars/algorethmpwd/R00tGlyph?style=social)](https://github.com/algorethmpwd/R00tGlyph)
[![Twitter Follow](https://img.shields.io/twitter/follow/rootglyph?style=social)](https://twitter.com/rootglyph)