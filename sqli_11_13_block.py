
# SQL Injection Level 11 - GraphQL Injection
@app.route("/sqli/level11", methods=["GET", "POST"])
@login_required
def sqli_level11():
    user = get_current_user()
    flag = None
    sqli_detected = False
    query_result = None
    
    if request.method == "POST":
        graphql_query = request.form.get("query", "")
        
        # Simulate GraphQL SQLi vulnerability
        # Vulnerable pattern: Direct concatenation in resolver
        if "sql_inject" in graphql_query.lower() or "' or 1=1" in graphql_query.lower():
             # Basic check for the specific bypass string usually taught
             if "' OR '1'='1" in graphql_query or '" OR "1"="1' in graphql_query:
                 sqli_detected = True
        
        # Mock Response
        if sqli_detected:
            query_result = {
                "data": {
                    "users": [
                        {"id": 1, "username": "admin", "apiKey": "FLAG{gr4phql_sql_1nj3ct10n_succ3ss}"},
                        {"id": 2, "username": "user", "apiKey": "user_key_123"}
                    ]
                }
            }
             # Mark completed
            challenge = Challenge.query.filter_by(name="GraphQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
        else:
            query_result = {
                "data": {
                    "users": []
                },
                "errors": [{"message": "Invalid query syntax or no results."}]
            }

    # Get flag if completed
    challenge = Challenge.query.filter_by(name="GraphQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)

    return render_template(
        "sqli/sqli_level11.html",
        flag=flag,
        sqli_detected=sqli_detected,
        query_result=query_result
    )

# SQL Injection Level 12 - ORM Injection
@app.route("/sqli/level12", methods=["GET", "POST"])
@login_required
def sqli_level12():
    user = get_current_user()
    flag = None
    sqli_detected = False
    products = []
    
    if request.method == "POST":
        # Vulnerable param filter
        order_by = request.form.get("order_by", "name")
        
        # Simulate ORM Injection in order_by clause
        # If user passes `name); DELETE FROM...` style or specific payload
        if "sleep(" in order_by.lower() or "benchmark(" in order_by.lower() or "1=1" in order_by:
             sqli_detected = True
        
        if sqli_detected:
             # Mark completed
            challenge = Challenge.query.filter_by(name="ORM-based SQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
    
    # Get flag if completed
    challenge = Challenge.query.filter_by(name="ORM-based SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)

    return render_template(
        "sqli/sqli_level12.html",
        flag=flag,
        sqli_detected=sqli_detected
    )

# SQL Injection Level 13 - Out-of-band SQL Injection
@app.route("/sqli/level13", methods=["GET", "POST"])
@login_required
def sqli_level13():
    user = get_current_user()
    flag = None
    sqli_detected = False
    
    if request.method == "POST":
        payload = request.form.get("tracking_id", "")
        
        # Detection for typical OOB vectors like DNS logging calls
        # e.g., Oracle: UTL_HTTP.REQUEST, MSSQL: xp_dirtree, MySQL: LOAD_FILE
        oob_sig = ["http_request", "dns_lookup", "xp_dirtree", "load_file"]
        
        for sig in oob_sig:
            if sig in payload.lower():
                sqli_detected = True
                break
        
        if sqli_detected:
            # Mark completed
            challenge = Challenge.query.filter_by(name="Out-of-band SQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)

    # Get flag if completed
    challenge = Challenge.query.filter_by(name="Out-of-band SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)

    return render_template(
        "sqli/sqli_level13.html",
        flag=flag,
        sqli_detected=sqli_detected
    )
