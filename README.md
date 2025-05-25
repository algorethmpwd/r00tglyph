# R00tGlyph - Advanced Web Security Training Platform

R00tGlyph is a comprehensive web security training platform designed to help security professionals, developers, and ethical hackers learn and practice various web application vulnerabilities in a controlled environment. All challenges are based on current 2024-2025 vulnerability trends and real-world scenarios.

## Features

- **69 Comprehensive Challenges**: 23 levels each for XSS, SQL Injection, and Command Injection
- **Modern Vulnerability Contexts**: Challenges simulate real-world applications (fintech, healthcare, e-commerce, cloud platforms)
- **Tool Integration**: Levels require use of industry-standard tools (Burp Suite, SQLMap, Nmap, etc.)
- **Progressive Difficulty**: From beginner to expert level challenges
- **User Progress Tracking**: Track your progress and achievements across all categories
- **Flag-based Challenges**: Each challenge has a unique flag to capture
- **Responsive Design**: Works on desktop and mobile devices with full dark mode support
- **Clean Architecture**: Streamlined codebase with single database management

## Challenge Categories

### Cross-Site Scripting (XSS) - 23 Levels
Modern web application XSS vulnerabilities covering:
- **Levels 1-3**: Basic reflected, DOM-based, and stored XSS in modern frameworks
- **Levels 4-6**: Filter bypass techniques in enterprise applications
- **Levels 7-9**: Advanced techniques (HTTP headers, JSON APIs, CSP bypass)
- **Levels 10-15**: Expert techniques (mutation observers, SVG, blind XSS, PDF generation, prototype pollution, template injection)
- **Levels 16-23**: Cutting-edge contexts (WebAssembly, PWAs, Web Components, GraphQL, WebRTC, Web APIs, WebGPU, federated identity)

### SQL Injection (SQLi) - 23 Levels
Modern database injection vulnerabilities covering:
- **Levels 1-4**: Basic injection, search, UNION, and blind techniques
- **Levels 5-8**: Advanced techniques (time-based, WAF bypass, second-order, JSON parameters)
- **Levels 9-15**: Expert techniques with tools (SQLMap, stored procedures, ORM, XML, Burp Suite, column names, ORDER BY, error-based)
- **Levels 16-23**: Modern contexts (LIMIT clause, boolean-based blind, subqueries, out-of-band, GraphQL, NoSQL, cloud databases)

### Command Injection (CMDi) - 23 Levels
Modern system command injection vulnerabilities covering:
- **Levels 1-4**: Basic injection, filters, blind techniques, file upload chaining
- **Levels 5-8**: Advanced techniques (API parameters, WAF bypass, time-based, Burp Suite integration)
- **Levels 9-15**: Expert techniques (JSON APIs, environment variables, XML processing, Nmap integration, GraphQL, WebSockets, serverless)
- **Levels 16-23**: Modern contexts (process substitution, containers, template engines, message queues, out-of-band, cloud functions, SSH, advanced chaining)

## Tools Integration

R00tGlyph challenges are designed to work with real bug bounty and penetration testing tools:
- **Burp Suite**: Web application security testing
- **SQLMap**: Automated SQL injection testing
- **Nmap**: Network discovery and security auditing
- **Nuclei**: Vulnerability scanner
- **FFUF**: Web fuzzer
- **Gobuster**: Directory/file enumeration
- **Sublist3r**: Subdomain enumeration
- **Waybackurls**: Historical URL discovery

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/algorethmpwd/R00tGlyph.git
   cd R00tGlyph
   ```
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python app.py
   ```
4. Open your browser and navigate to `http://localhost:5000`

### Additional Commands

The application supports several command-line arguments:

```
python app.py -h                # Show help menu
python app.py --update          # Update R00tGlyph to the latest version
python app.py --backup          # Backup user data
python app.py --restore         # Restore user data from backup
python app.py --reset           # Reset the database to its initial state
```

## Requirements

- Python 3.7+
- Flask
- Flask-SQLAlchemy

## Educational Purpose

This platform is designed for educational purposes only. The skills learned should only be applied to systems you have permission to test.

## Upcoming Features

- CSRF vulnerabilities
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE) Injection
- Server-Side Template Injection (SSTI)
- Insecure Deserialization
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)

## User Progress and Challenge Management

R00tGlyph includes a comprehensive user progress tracking system:

- Challenges are numbered sequentially on the challenges page for easy navigation
- When a challenge is completed, it is automatically marked as complete
- User profile page displays all completed challenges and remaining challenges
- Username changes propagate throughout the application
- Accurate statistics tracking for completed and incomplete challenges
- Challenge flags are only revealed upon successful completion
- All challenges have detailed descriptions in popups
- Every challenge has a corresponding solution page with detailed explanations
- The update mechanism preserves user progress when updating to the latest version

## Repository

The R00tGlyph project is hosted on GitHub:
- Repository URL: https://github.com/algorethmpwd/R00tGlyph
- To contribute or report issues, please use the GitHub issue tracker

## Credits

Created by [Algorethm](https://youtube.com/@algorethm_) | [Telegram](https://t.me/hackerpwd1)
