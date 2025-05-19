# SQL Injection Level 15 - SQL Injection via XML
@app.route('/sqli/level15', methods=['GET', 'POST'])
def sqli_level15():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    xml_data = None
    reports = []
    error = None
    
    if request.method == 'POST':
        xml_data = request.form.get('xml_data', '')
        
        # Check if the XML is well-formed
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)
            
            # Extract values from XML
            report_type = root.find('type').text if root.find('type') is not None else ''
            report_period = root.find('period').text if root.find('period') is not None else ''
            report_department = root.find('department').text if root.find('department') is not None else ''
            
            # Check for SQL injection patterns in XML values
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "="]
            
            for pattern in sqli_patterns:
                if (pattern in report_type or pattern in report_period or pattern in report_department):
                    # SQL injection detected!
                    sqli_detected = True
                    
                    # Add the restricted report (with the flag)
                    reports.append({
                        "id": 999, 
                        "title": "Restricted Financial Report", 
                        "type": "confidential", 
                        "period": "annual", 
                        "department": "executive",
                        "data": "This report contains the flag: R00T{xml_sql1_1nj3ct10n_3xpl01t3d}"
                    })
                    
                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SQL Injection via XML").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            
            # If no SQL injection detected, return normal reports
            if not sqli_detected:
                if report_type == 'sales':
                    reports = [
                        {"id": 1, "title": "Sales Report Q1", "type": "sales", "period": "quarterly", "department": report_department, "data": "Sales increased by 15% in Q1."},
                        {"id": 2, "title": "Sales Report Q2", "type": "sales", "period": "quarterly", "department": report_department, "data": "Sales increased by 10% in Q2."}
                    ]
                elif report_type == 'inventory':
                    reports = [
                        {"id": 3, "title": "Inventory Status", "type": "inventory", "period": report_period, "department": report_department, "data": "Current inventory levels are optimal."},
                        {"id": 4, "title": "Inventory Forecast", "type": "inventory", "period": report_period, "department": report_department, "data": "Inventory forecast for next quarter is stable."}
                    ]
                elif report_type == 'marketing':
                    reports = [
                        {"id": 5, "title": "Marketing Campaign Results", "type": "marketing", "period": report_period, "department": report_department, "data": "Recent campaign resulted in 20% increase in leads."},
                        {"id": 6, "title": "Marketing Budget", "type": "marketing", "period": report_period, "department": report_department, "data": "Marketing budget allocation for next quarter."}
                    ]
        except Exception as e:
            error = f"Error processing XML: {str(e)}"
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection via XML").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level15.html', flag=flag, sqli_detected=sqli_detected,
                          xml_data=xml_data, reports=reports, error=error)
