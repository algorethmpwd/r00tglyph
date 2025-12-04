#!/usr/bin/env python
"""
SQL Injection Template Generator - All Levels 1-23
Generates all SQLi challenge templates with tailored hints
"""

# SQL Injection Challenge Data
sqli_challenges = [
    {
        "level": 1, "title": "Basic Authentication Bypass", "app_name": "SecureBank", "url": "securebank.local/login",
        "objective": "Bypass login authentication using SQL injection",
        "hints": [
            {"title": "Understanding SQL Injection", "icon": "lightbulb", "content": "SQL injection occurs when user input is directly concatenated into SQL queries. The login query likely looks like: <code>SELECT * FROM users WHERE username='INPUT' AND password='INPUT'</code>. Your goal is to make this query always return true."},
            {"title": "Authentication Bypass Technique", "icon": "code-slash", "content": "Try using: <code>' OR '1'='1</code> in the username field. This closes the username string and adds a condition that's always true. The query becomes: <code>WHERE username='' OR '1'='1' AND password='...'</code>"},
            {"title": "Solution", "icon": "shield-check", "content": "<strong>Step-by-step:</strong><ol class='mb-2 mt-2'><li>Enter <code>' OR '1'='1' --</code> in the username field</li><li>Enter anything in the password field</li><li>The <code>--</code> comments out the password check</li><li>You'll be logged in as the first user in the database</li></ol><strong>Why it works:</strong> The query becomes <code>WHERE username='' OR '1'='1' --' AND password='...'</code>, which always evaluates to true."}
        ]
    },
    {
        "level": 2, "title": "UNION-based SQL Injection", "app_name": "ProductCatalog", "url": "catalog.local/search",
        "objective": "Extract data using UNION SELECT",
        "hints": [
            {"title": "UNION SELECT Basics", "icon": "lightbulb", "content": "UNION allows combining results from multiple SELECT statements. First, determine the number of columns in the original query by using: <code>' ORDER BY 1--</code>, <code>' ORDER BY 2--</code>, etc. until you get an error."},
            {"title": "Extracting Data", "icon": "code-slash", "content": "Once you know the column count, use UNION to extract data: <code>' UNION SELECT username, password FROM users--</code>. Match the number of columns in your UNION with the original query."},
            {"title": "Solution", "icon": "shield-check", "content": "<strong>Step-by-step:</strong><ol class='mb-2 mt-2'><li>Find column count: <code>' ORDER BY 3--</code> (adjust until no error)</li><li>Use UNION: <code>' UNION SELECT 1,username,password FROM users--</code></li><li>View the results to see extracted user data</li></ol><strong>Why it works:</strong> UNION combines your malicious SELECT with the original query, displaying sensitive data."}
        ]
    },
    {
        "level": 3, "title": "Blind SQL Injection (Boolean)", "app_name": "NewsPortal", "url": "news.local/article",
        "objective": "Extract data using boolean-based blind SQLi",
        "hints": [
            {"title": "Blind SQLi Concept", "icon": "lightbulb", "content": "Blind SQLi occurs when you can't see query results directly, but can infer information from the application's behavior. Test with: <code>' AND '1'='1</code> (true) vs <code>' AND '1'='2</code> (false). Different responses indicate vulnerability."},
            {"title": "Data Extraction", "icon": "code-slash", "content": "Extract data character by character using: <code>' AND SUBSTRING(username,1,1)='a'--</code>. If the page behaves normally, the first character is 'a'. Repeat for each character."},
            {"title": "Solution", "icon": "shield-check", "content": "<strong>Step-by-step:</strong><ol class='mb-2 mt-2'><li>Test: <code>?id=1' AND '1'='1'--</code> (page loads normally)</li><li>Test: <code>?id=1' AND '1'='2'--</code> (page behaves differently)</li><li>Extract: <code>?id=1' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--</code></li><li>Iterate through alphabet for each position</li></ol><strong>Why it works:</strong> Boolean conditions reveal information through application behavior changes."}
        ]
    },
    {
        "level": 4, "title": "Time-based Blind SQL Injection", "app_name": "UserDirectory", "url": "directory.local/lookup",
        "objective": "Use time delays to extract data",
        "hints": [
            {"title": "Time-based Technique", "icon": "lightbulb", "content": "When boolean-based blind SQLi doesn't work, use time delays. Inject: <code>' AND SLEEP(5)--</code> (MySQL) or <code>' AND pg_sleep(5)--</code> (PostgreSQL). If the page delays 5 seconds, you have SQLi."},
            {"title": "Conditional Delays", "icon": "code-slash", "content": "Extract data using conditional delays: <code>' AND IF(SUBSTRING(password,1,1)='a',SLEEP(5),0)--</code>. If it delays, the first character is 'a'."},
            {"title": "Solution", "icon": "shield-check", "content": "<strong>Step-by-step:</strong><ol class='mb-2 mt-2'><li>Test: <code>?id=1' AND SLEEP(5)--</code> (page delays 5 seconds)</li><li>Extract: <code>?id=1' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(3),0)--</code></li><li>Iterate through characters, noting delays</li></ol><strong>Why it works:</strong> Time delays reveal information when no other output is available."}
        ]
    },
    {
        "level": 5, "title": "Error-based SQL Injection", "app_name": "InventorySystem", "url": "inventory.local/item",
        "objective": "Extract data through error messages",
        "hints": [
            {"title": "Error-based Extraction", "icon": "lightbulb", "content": "Some applications display SQL error messages. Use functions that cause errors containing your data: <code>' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 1)))--</code>"},
            {"title": "Database-specific Functions", "icon": "code-slash", "content": "MySQL: <code>extractvalue()</code>, <code>updatexml()</code>. PostgreSQL: <code>CAST()</code> errors. MSSQL: <code>CONVERT()</code> errors. Each database has functions that can leak data in errors."},
            {"title": "Solution", "icon": "shield-check", "content": "<strong>Step-by-step:</strong><ol class='mb-2 mt-2'><li>Trigger error: <code>?id=1'</code> (see if errors are displayed)</li><li>Extract data: <code>?id=1' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 1)))--</code></li><li>Read the password from the error message</li></ol><strong>Why it works:</strong> Error messages inadvertently display the data you're querying."}
        ]
    },
    {
        "level": 6, "title": "Second-order SQL Injection", "app_name": "ForumApp", "url": "forum.local/profile",
        "objective": "Exploit stored SQL injection",
        "hints": [
            {"title": "Second-order SQLi", "icon": "lightbulb", "content": "Second-order SQLi occurs when malicious input is stored safely but later used unsafely. Register with username: <code>admin'--</code>, then trigger it in another query."},
            {"title": "Finding the Trigger", "icon": "code-slash", "content": "The injection point (registration) is different from the execution point (profile view, search, etc.). Look for features that use your stored data in queries."},
            {"title": "Solution", "icon": "shield-check", "content": "<strong>Step-by-step:</strong><ol class='mb-2 mt-2'><li>Register with username: <code>admin'--</code></li><li>Navigate to a feature that queries your username</li><li>The stored payload executes in the new context</li></ol><strong>Why it works:</strong> Input validation at storage doesn't prevent execution in different contexts."}
        ]
    },
    {
        "level": 7, "title": "SQL Injection in INSERT", "app_name": "RegistrationPortal", "url": "register.local/signup",
        "objective": "Inject into INSERT statements",
        "hints": [
            {"title": "INSERT Injection", "icon": "lightbulb", "content": "INSERT statements can be vulnerable too. The query might be: <code>INSERT INTO users (username, email) VALUES ('INPUT', 'INPUT')</code>. You can inject additional columns or values."},
            {"title": "Multi-statement Injection", "icon": "code-slash", "content": "Try: <code>test', 'test@test.com'); INSERT INTO users (username, password, role) VALUES ('hacker', 'pass', 'admin')--</code> to inject a new admin user."},
            {"title": "Solution", "icon": "shield-check", "content": "<strong>Step-by-step:</strong><ol class='mb-2 mt-2'><li>In username field: <code>test', 'test@test.com'); INSERT INTO users VALUES ('admin', 'password', 'admin')--</code></li><li>Complete registration</li><li>Login as the newly created admin user</li></ol><strong>Why it works:</strong> Multiple statements execute, creating your malicious user."}
        ]
    },
    {
        "level": 8, "title": "SQL Injection in UPDATE", "app_name": "ProfileManager", "url": "profile.local/update",
        "objective": "Exploit UPDATE statement vulnerabilities",
        "hints": [
            {"title": "UPDATE Injection", "icon": "lightbulb", "content": "UPDATE queries: <code>UPDATE users SET email='INPUT' WHERE id=1</code>. You can modify other columns: <code>test', role='admin' WHERE '1'='1</code>"},
            {"title": "Privilege Escalation", "icon": "code-slash", "content": "Change your role to admin: <code>user@test.com', role='admin'--</code> in the email field."},
            {"title": "Solution", "icon": "shield-check", "content": "<strong>Step-by-step:</strong><ol class='mb-2 mt-2'><li>In email field: <code>test@test.com', role='admin' WHERE username='youruser'--</code></li><li>Submit the update</li><li>Refresh and verify you now have admin privileges</li></ol><strong>Why it works:</strong> You inject additional SET clauses to modify unintended columns."}
        ]
    },
    {
        "level": 9, "title": "SQL Injection in DELETE", "app_name": "ContentManager", "url": "content.local/delete",
        "objective": "Exploit DELETE statement vulnerabilities",
        "hints": [
            {"title": "DELETE Injection", "icon": "lightbulb", "content": "DELETE queries: <code>DELETE FROM posts WHERE id='INPUT'</code>. Dangerous because you can delete all records: <code>1' OR '1'='1</code>"},
            {"title": "Selective Deletion", "icon": "code-slash", "content": "Delete specific records: <code>1' OR author='admin'--</code> to delete all admin posts."},
            {"title": "Solution", "icon": "shield-check", "content": "<strong>Step-by-step:</strong><ol class='mb-2 mt-2'><li>In ID field: <code>1' OR '1'='1'--</code></li><li>All records matching the condition are deleted</li><li>Use carefully in testing!</li></ol><strong>Why it works:</strong> The WHERE clause becomes always true, deleting all records."}
        ]
    },
    {
        "level": 10, "title": "SQL Injection with WAF Bypass", "app_name": "ProtectedDB", "url": "protected.local/query",
        "objective": "Bypass Web Application Firewall",
        "hints": [
            {"title": "WAF Detection", "icon": "lightbulb", "content": "WAFs block common SQLi patterns. Test what's blocked: <code>UNION</code>, <code>SELECT</code>, <code>OR</code>, etc. Then find bypass techniques."},
            {"title": "Bypass Techniques", "icon": "code-slash", "content": "Use: Case variations (<code>UnIoN</code>), comments (<code>UN/**/ION</code>), encoding (<code>%55NION</code>), or alternative syntax (<code>||</code> instead of <code>OR</code>)."},
            {"title": "Solution", "icon": "shield-check", "content": "<strong>Bypass examples:</strong><ul class='mb-2 mt-2'><li><code>' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--</code></li><li><code>' %55NION %53ELECT 1,2,3--</code></li><li><code>' UNION/**/SELECT/**/1,2,3--</code></li></ul><strong>Why it works:</strong> WAF rules miss obfuscated variations."}
        ]
    }
]

# Add levels 11-23 with advanced techniques
advanced_sqli = [
    {"level": 11, "title": "NoSQL Injection (MongoDB)", "app_name": "MongoApp", "url": "mongo.local/find",
     "objective": "Exploit NoSQL injection in MongoDB",
     "hints": [
         {"title": "NoSQL Injection", "icon": "lightbulb", "content": "NoSQL databases like MongoDB use JSON queries. Inject operators: <code>{\"username\": {\"$ne\": null}}</code> to bypass authentication."},
         {"title": "MongoDB Operators", "icon": "code-slash", "content": "Use <code>$ne</code> (not equal), <code>$gt</code> (greater than), <code>$regex</code> for injection. Example: <code>username[$ne]=null&password[$ne]=null</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "In login form, use: <code>username[$ne]=null&password[$ne]=null</code> to bypass authentication by making the query always match."}
     ]},
    {"level": 12, "title": "ORM Injection", "app_name": "DjangoApp", "url": "django.local/filter",
     "objective": "Exploit ORM query vulnerabilities",
     "hints": [
         {"title": "ORM Vulnerabilities", "icon": "lightbulb", "content": "ORMs like Django, SQLAlchemy can be vulnerable when using raw queries or unsafe filters. Look for <code>.raw()</code> or <code>.extra()</code> methods."},
         {"title": "Filter Injection", "icon": "code-slash", "content": "Django example: <code>?username__startswith=admin&username__regex=.*</code> to manipulate query logic."},
         {"title": "Solution", "icon": "shield-check", "content": "Exploit unsafe ORM usage by injecting filter operators that bypass intended logic."}
     ]},
    {"level": 13, "title": "SQL Injection in JSON", "app_name": "APIGateway", "url": "api.local/json",
     "objective": "Inject through JSON parameters",
     "hints": [
         {"title": "JSON SQL Injection", "icon": "lightbulb", "content": "APIs accepting JSON can be vulnerable if values are used in SQL queries. Test: <code>{\"id\": \"1' OR '1'='1\"}</code>"},
         {"title": "JSON Payload", "icon": "code-slash", "content": "Send: <code>{\"username\": \"admin' --\", \"password\": \"anything\"}</code> in POST body."},
         {"title": "Solution", "icon": "shield-check", "content": "Inject SQL in JSON values that get used in backend queries without proper sanitization."}
     ]},
    {"level": 14, "title": "SQL Injection in XML", "app_name": "SOAPService", "url": "soap.local/request",
     "objective": "Exploit SQL injection in XML/SOAP",
     "hints": [
         {"title": "XML SQLi", "icon": "lightbulb", "content": "SOAP/XML services can be vulnerable. Inject in XML elements: <code>&lt;username&gt;admin' OR '1'='1&lt;/username&gt;</code>"},
         {"title": "XML Payload", "icon": "code-slash", "content": "Craft XML with SQLi: <code>&lt;user&gt;&lt;name&gt;admin'--&lt;/name&gt;&lt;pass&gt;x&lt;/pass&gt;&lt;/user&gt;</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Inject SQL payloads within XML elements that are processed by backend SQL queries."}
     ]},
    {"level": 15, "title": "SQL Injection via Cookies", "app_name": "SessionApp", "url": "session.local/dashboard",
     "objective": "Inject through cookie values",
     "hints": [
         {"title": "Cookie Injection", "icon": "lightbulb", "content": "Cookies can be used in SQL queries. Modify cookie values: <code>user_id=1' OR '1'='1'--</code>"},
         {"title": "Cookie Manipulation", "icon": "code-slash", "content": "Use browser DevTools or Burp Suite to modify cookies before requests."},
         {"title": "Solution", "icon": "shield-check", "content": "Change cookie value to: <code>session=abc'; UPDATE users SET role='admin' WHERE id=1--</code>"}
     ]},
    {"level": 16, "title": "SQL Injection in ORDER BY", "app_name": "SortableList", "url": "list.local/sort",
     "objective": "Exploit ORDER BY clause injection",
     "hints": [
         {"title": "ORDER BY Injection", "icon": "lightbulb", "content": "ORDER BY clauses can leak data: <code>?sort=username</code> becomes <code>ORDER BY username</code>. Inject: <code>?sort=(SELECT CASE WHEN (1=1) THEN username ELSE email END)</code>"},
         {"title": "Boolean Extraction", "icon": "code-slash", "content": "Use CASE statements in ORDER BY to extract data based on conditions."},
         {"title": "Solution", "icon": "shield-check", "content": "Inject conditional ORDER BY to infer data through sort order changes."}
     ]},
    {"level": 17, "title": "SQL Injection in GROUP BY", "app_name": "Analytics", "url": "analytics.local/report",
     "objective": "Exploit GROUP BY clause vulnerabilities",
     "hints": [
         {"title": "GROUP BY Injection", "icon": "lightbulb", "content": "GROUP BY can be exploited similarly to ORDER BY. Inject expressions that reveal data."},
         {"title": "Aggregation Abuse", "icon": "code-slash", "content": "Use HAVING clause with injected conditions to filter results."},
         {"title": "Solution", "icon": "shield-check", "content": "Inject into GROUP BY or HAVING to manipulate query logic and extract data."}
     ]},
    {"level": 18, "title": "SQL Injection in LIMIT", "app_name": "Pagination", "url": "page.local/results",
     "objective": "Exploit LIMIT clause injection",
     "hints": [
         {"title": "LIMIT Injection", "icon": "lightbulb", "content": "LIMIT clauses can sometimes be exploited: <code>LIMIT 10 OFFSET 0; SELECT password FROM users--</code>"},
         {"title": "Stacked Queries", "icon": "code-slash", "content": "If stacked queries are allowed, inject additional statements after LIMIT."},
         {"title": "Solution", "icon": "shield-check", "content": "Inject stacked queries or use LIMIT with UNION to extract data."}
     ]},
    {"level": 19, "title": "Stored Procedure Injection", "app_name": "LegacyDB", "url": "legacy.local/proc",
     "objective": "Exploit stored procedure vulnerabilities",
     "hints": [
         {"title": "Stored Procedures", "icon": "lightbulb", "content": "Stored procedures can be vulnerable if they use dynamic SQL internally. Test parameters for SQLi."},
         {"title": "Procedure Exploitation", "icon": "code-slash", "content": "Inject into procedure parameters: <code>EXEC GetUser 'admin'' OR ''1''=''1'</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Find procedures using dynamic SQL and inject through their parameters."}
     ]},
    {"level": 20, "title": "SQL Injection via User-Agent", "app_name": "LoggingApp", "url": "logging.local/visit",
     "objective": "Inject through HTTP headers",
     "hints": [
         {"title": "Header Injection", "icon": "lightbulb", "content": "Applications logging HTTP headers (User-Agent, Referer, X-Forwarded-For) might be vulnerable if logs are queried."},
         {"title": "Header Manipulation", "icon": "code-slash", "content": "Set User-Agent to: <code>Mozilla' OR '1'='1'--</code> and trigger a query on logs."},
         {"title": "Solution", "icon": "shield-check", "content": "Inject SQL in headers that get stored and later queried without sanitization."}
     ]},
    {"level": 21, "title": "SQL Truncation Attack", "app_name": "UserReg", "url": "userreg.local/create",
     "objective": "Exploit SQL truncation vulnerabilities",
     "hints": [
         {"title": "Truncation Attack", "icon": "lightbulb", "content": "If username field is VARCHAR(20), entering 'admin' + 15 spaces + 'x' gets truncated to 'admin' + spaces, potentially creating duplicate admin."},
         {"title": "Exploitation", "icon": "code-slash", "content": "Register as: <code>admin[spaces]x</code> where total length exceeds column limit."},
         {"title": "Solution", "icon": "shield-check", "content": "Exploit truncation to create accounts with privileged usernames."}
     ]},
    {"level": 22, "title": "SQL Injection with Encoding", "app_name": "EncodedInput", "url": "encoded.local/search",
     "objective": "Bypass filters using encoding",
     "hints": [
         {"title": "Encoding Techniques", "icon": "lightbulb", "content": "Use URL encoding, Unicode, or hex encoding to bypass filters. Example: <code>%27%20OR%20%271%27%3D%271</code>"},
         {"title": "Double Encoding", "icon": "code-slash", "content": "Try double encoding: <code>%2527</code> (encoded apostrophe) might bypass some filters."},
         {"title": "Solution", "icon": "shield-check", "content": "Encode payloads to evade input validation while still executing SQL injection."}
     ]},
    {"level": 23, "title": "Advanced Polyglot SQLi", "app_name": "MultiDB", "url": "multidb.local/query",
     "objective": "Create database-agnostic payloads",
     "hints": [
         {"title": "Polyglot Payloads", "icon": "lightbulb", "content": "Polyglot SQLi works across multiple databases (MySQL, PostgreSQL, MSSQL). Use syntax compatible with all."},
         {"title": "Universal Syntax", "icon": "code-slash", "content": "Example: <code>' OR '1'='1'--</code> works on most databases. Avoid database-specific functions."},
         {"title": "Solution", "icon": "shield-check", "content": "Craft payloads using standard SQL that execute on any database system."}
     ]}
]

sqli_challenges.extend(advanced_sqli)

def generate_sqli_template(challenge):
    hints_html = ""
    for i, hint in enumerate(challenge['hints'], 1):
        hints_html += f"""
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                            data-bs-target="#hint{i}">
                            <i class="bi bi-{hint['icon']} me-2"></i> Hint {i}: {hint['title']}
                        </button>
                    </h2>
                    <div id="hint{i}" class="accordion-collapse collapse" data-bs-parent="#hintsAccordion">
                        <div class="accordion-body small text-secondary">
                            {hint['content']}
                        </div>
                    </div>
                </div>"""
    
    template = f"""{{%extends 'base.html' %}}

{{%block title %}}Level {challenge['level']}: {challenge['title']} - R00tGlyph{{%endblock %}}

{{%block breadcrumb %}}
<span class="text-muted">Challenges</span> / <span class="text-muted">SQL Injection</span> / <span>Level {challenge['level']}</span>
{{%endblock %}}

{{%block content %}}
<div class="challenge-lab">
    <!-- LEFT PANEL: Mission & Intel -->
    <div class="mission-panel">
        <div class="mission-header">
            <i class="bi bi-crosshair me-2"></i>Mission Control
        </div>
        <div class="mission-content">
            <h5 class="mb-3">{challenge['title']}</h5>
            <p class="text-secondary small mb-4">
                Welcome to <strong>{challenge['app_name']}</strong>. Test for SQL injection vulnerabilities.
            </p>

            <div class="card mb-4 border-0 bg-light">
                <div class="card-body p-3">
                    <h6 class="card-title small text-uppercase text-muted mb-2">Objective</h6>
                    <p class="mb-0 small">{challenge['objective']}</p>
                </div>
            </div>

            <!-- Integrated Hints System -->
            <div class="hint-accordion accordion" id="hintsAccordion">{hints_html}
            </div>

            {{%if sqli_detected %}}
            <div class="flag-success mt-4">
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i class="bi bi-check-circle-fill text-success"></i>
                    <strong>Mission Accomplished!</strong>
                </div>
                <p class="small text-secondary mb-2">You've successfully exploited the SQL injection vulnerability.</p>
                {{%if flag %}}
                <span class="flag-value">{{{{ flag }}}}</span>
                {{%endif %}}
            </div>
            {{%endif %}}
        </div>
    </div>

    <!-- RIGHT PANEL: The Vulnerable App -->
    <div class="work-panel">
        <div class="browser-bar">
            <div class="d-flex gap-2 text-secondary">
                <i class="bi bi-arrow-left"></i>
                <i class="bi bi-arrow-right"></i>
                <i class="bi bi-arrow-clockwise"></i>
            </div>
            <div class="url-bar">
                <i class="bi bi-lock-fill text-success me-2 small"></i>
                <span>{challenge['url']}</span>
            </div>
        </div>

        <div class="app-frame p-4">
            <p class="text-muted">Challenge interface for SQLi Level {challenge['level']}</p>
        </div>
    </div>
</div>
{{%endblock %}}
"""
    return template

if __name__ == '__main__':
    import os
    
    template_dir = 'templates/sqli'
    os.makedirs(template_dir, exist_ok=True)
    
    for challenge in sqli_challenges:
        template_content = generate_sqli_template(challenge)
        filename = f"{template_dir}/sqli_level{challenge['level']}.html"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(template_content)
        
        print(f"✅ Generated {filename}")
    
    print(f"\n✅ Successfully generated {len(sqli_challenges)} SQLi templates (Levels 1-23)!")
