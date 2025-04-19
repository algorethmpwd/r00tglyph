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

## Current Vulnerability Types

- **Cross-Site Scripting (XSS)**
  - Level 1: Basic Reflected XSS
  - Level 2: DOM-based XSS
  - Level 3: Stored XSS
  - Level 4: XSS with Basic Filters
  - Level 5: XSS with Advanced Filters
  - Level 6: XSS with ModSecurity WAF

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python app.py
   ```
4. Open your browser and navigate to `http://localhost:5000`

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

## Credits

Created by [Algorethm](https://youtube.com/@algorethm_) | [Telegram](https://t.me/hackerpwd1)
