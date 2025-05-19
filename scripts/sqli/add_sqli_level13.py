#!/usr/bin/env python3
from app import app, db

def add_sqli_level13_route():
    """Add the SQL Injection Level 13 route to app.py"""
    # Find the end of the sqli_level12 function
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the end of the sqli_level12 function
    sqli_level12_end = content.find("    return render_template('sqli/sqli_level12.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level12_end = content.find("\n", sqli_level12_end + 1)
    
    # Add the sqli_level13 function after sqli_level12
    new_route = '''
# SQL Injection Level 13 - Out-of-band SQL Injection
@app.route('/sqli/level13', methods=['GET', 'POST'])
def sqli_level13():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    search_term = request.form.get('search_term', '')
    stocks = []
    error = None
    dns_logs = []
    
    # Default stocks
    default_stocks = [
        {
            "symbol": "AAPL",
            "name": "Apple Inc.",
            "price": "182.63",
            "change": 1.25
        },
        {
            "symbol": "MSFT",
            "name": "Microsoft Corporation",
            "price": "337.22",
            "change": 0.87
        },
        {
            "symbol": "GOOGL",
            "name": "Alphabet Inc.",
            "price": "131.86",
            "change": -0.32
        },
        {
            "symbol": "AMZN",
            "name": "Amazon.com, Inc.",
            "price": "127.74",
            "change": 0.56
        },
        {
            "symbol": "TSLA",
            "name": "Tesla, Inc.",
            "price": "237.49",
            "change": -1.45
        }
    ]
    
    # Handle search request (POST)
    if request.method == 'POST':
        # Check for SQL injection patterns in the search term
        sqli_patterns = ["'", "\"", "--", ";", "UNION", "SELECT", "FROM", "WHERE", "DROP", "INSERT", "DELETE", "UPDATE", 
                         "LOAD_FILE", "UTL_HTTP", "xp_dirtree", "sp_OAMethod", "UTL_INADDR", "attacker.com"]
        
        # Convert to uppercase for case-insensitive check
        search_term_upper = search_term.upper() if isinstance(search_term, str) else ""
        
        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in search_term_upper:
                # SQL injection detected!
                sqli_detected = True
                break
        
        # Simulate stock search
        if search_term:
            if sqli_detected:
                # SQL injection successful - simulate DNS exfiltration
                dns_logs = [
                    {
                        "timestamp": "2023-07-15 14:32:18",
                        "query": "db-server.local",
                        "type": "A",
                        "source": "192.168.1.10"
                    },
                    {
                        "timestamp": "2023-07-15 14:32:19",
                        "query": "R00T{0ut_0f_b4nd_sql1_3xf1ltr4t10n}.attacker.com",
                        "type": "A",
                        "source": "192.168.1.10"
                    }
                ]
                
                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="Out-of-band SQL Injection").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
                
                # Return all stocks for the search results
                stocks = default_stocks
            else:
                # Normal search - filter stocks by symbol or name
                for stock in default_stocks:
                    if search_term.upper() in stock["symbol"].upper() or search_term.lower() in stock["name"].lower():
                        stocks.append(stock)
                
                if not stocks:
                    error = f"No stocks found matching '{search_term}'."
        else:
            # No search term - show all stocks
            stocks = default_stocks
    else:
        # Default view - show all stocks
        stocks = default_stocks
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Out-of-band SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level13.html', flag=flag, sqli_detected=sqli_detected,
                          search_term=search_term, stocks=stocks, error=error, dns_logs=dns_logs)
'''
    
    # Insert the new route
    updated_content = content[:sqli_level12_end + 1] + new_route + content[sqli_level12_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Level 13 route to app.py")

if __name__ == '__main__':
    add_sqli_level13_route()
