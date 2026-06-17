import sqlite3, subprocess, os
from flask import render_template_string

def get_sqli_query(request):
    if 'username' in request.form and 'password' in request.form:
        return f"SELECT * FROM data WHERE username='{request.form.get('username')}' AND password='{request.form.get('password')}'"
    elif 'search_term' in request.form:
        return f"SELECT * FROM data WHERE name LIKE '%{request.form.get('search_term')}%'"
    elif 'search' in request.form:
        return f"SELECT * FROM data WHERE name LIKE '%{request.form.get('search')}%'"
    elif 'id' in request.args:
        return f"SELECT * FROM data WHERE id={request.args.get('id')}"
    return "SELECT * FROM data"

def process_sink(category, level, request):
    result = None
    is_exploited = False
    
    if category == 'sqli':
        query = get_sqli_query(request)
        try:
            conn = sqlite3.connect(':memory:')
            conn.execute("CREATE TABLE data (id INT, username TEXT, password TEXT, name TEXT, description TEXT, price REAL)")
            conn.execute("INSERT INTO data VALUES (1, 'admin', 'supersecret', 'Admin Product', 'Top secret', 999.99)")
            conn.execute("INSERT INTO data VALUES (2, 'user', 'password123', 'Normal Product', 'Boring', 9.99)")
            cursor = conn.execute(query)
            columns = [column[0] for column in cursor.description]
            result = [dict(zip(columns, row)) for row in cursor.fetchall()]
            if len(result) > 1 or any(r.get('username') == 'admin' for r in result):
                is_exploited = True
        except Exception as e:
            result = []
            if "syntax error" in str(e).lower() or "unrecognized token" in str(e).lower():
                is_exploited = True

    elif category == 'cmdi':
        command = request.form.get('command') or request.form.get('hostname') or request.args.get('ip') or ''
        if command:
            try:
                safe_cmd = f"timeout 2 sh -c '{command}'"
                output = subprocess.check_output(safe_cmd, shell=True, stderr=subprocess.STDOUT, text=True)
                result = output
                if "root" in output or "uid=" in output or "bin" in output:
                    is_exploited = True
            except Exception as e:
                result = str(e)
                if hasattr(e, 'output') and e.output and ("root" in e.output or "uid=" in e.output):
                    is_exploited = True

    elif category == 'xss':
        payload = request.form.get('payload') or request.form.get('name') or request.args.get('q') or ''
        result = payload
        if "<script>" in payload.lower() or "onerror" in payload.lower() or "javascript:" in payload.lower():
            is_exploited = True

    elif category == 'ssti':
        payload = request.form.get('payload') or ''
        try:
            result = render_template_string(payload)
            if "77" in result or "config" in result or "class" in result:
                is_exploited = True
        except:
            pass
            
    elif category == 'ssrf':
        url = request.form.get('url') or request.args.get('url') or ''
        result = f"Fetched {url}"
        if "127.0.0.1" in url or "localhost" in url or "metadata" in url:
            is_exploited = True

    return result, is_exploited
