# R00tGlyph

An advanced web security training platform for practicing and learning about web vulnerabilities in a safe, controlled environment.

## Overview

R00tGlyph is a Python-based web application designed to simulate real-world web vulnerabilities. It provides a CTF-style environment where users can practice exploiting vulnerabilities, earn points by capturing flags, and learn about security best practices.

## Features

- Progressive learning path from basic to advanced vulnerabilities
- CTF-style flag submission system with unique flags for each user
- Multiple dark themes (Dark, Cyberpunk, Hacker)
- Detailed explanations and solution guides
- Real-world context for advanced examples
- WAF emulation for advanced challenges
- User authentication and scoreboard
- Expandable framework for adding more vulnerability types
- Challenge tracking and completion status
- User profile with progress statistics

## Current Vulnerability Types

- **Cross-Site Scripting (XSS)**
  - Level 1: Basic Reflected XSS
  - Level 2: DOM-based XSS
  - Level 3: Stored XSS
  - Level 4: XSS with Basic Filters
  - Level 5: XSS with Advanced Filters
  - Level 6: XSS with ModSecurity WAF
  - Level 7: XSS via HTTP Headers
  - Level 8: XSS in JSON API
  - Level 9: XSS in Blog Comments
  - Level 10: XSS in Markdown Parser
  - Level 11: XSS via SVG and CDATA
  - Level 12: XSS in CSS Context
  - Level 14: XSS in JSON Configuration
  - Level 20: XSS in WebRTC Applications
  - Level 21: XSS via Web Bluetooth/USB
  - Level 22: XSS in WebGPU Applications

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

- SQL Injection challenges
- Command Injection challenges
- CSRF vulnerabilities
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE) Injection
- Server-Side Template Injection (SSTI)
- Insecure Deserialization

## User Progress and Challenge Management

R00tGlyph includes a comprehensive user progress tracking system:

- Challenges are numbered sequentially on the challenges page for easy navigation
- When a challenge is completed, it is automatically marked as complete
- User profile page displays all completed challenges and remaining challenges
- Username changes propagate throughout the application
- Accurate statistics tracking for completed and incomplete challenges
- Challenge flags are only revealed upon successful completion

## Repository

The R00tGlyph project is hosted on GitHub:
- Repository URL: https://github.com/algorethmpwd/R00tGlyph
- To contribute or report issues, please use the GitHub issue tracker

## Credits

Created by [Algorethm](https://youtube.com/@algorethm_) | [Telegram](https://t.me/hackerpwd1)
