# SQL Injection Level 19 - SQL Injection via File Upload
@app.route('/sqli/level19', methods=['GET', 'POST'])
def sqli_level19():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    csv_content = None
    csv_preview = []
    upload_success = False
    rows_processed = 0
    rows_imported = 0
    import_status = None
    import_errors = []
    import_output = None
    error = None
    
    if request.method == 'POST':
        csv_content = request.form.get('csv_content', '')
        
        if csv_content:
            try:
                # Parse the CSV content
                import csv
                from io import StringIO
                
                csv_file = StringIO(csv_content)
                csv_reader = csv.reader(csv_file)
                
                # Convert to list for preview
                csv_rows = list(csv_reader)
                
                if len(csv_rows) > 0:
                    # Set CSV preview (limit to 10 rows)
                    csv_preview = csv_rows[:10]
                    
                    # Process the CSV rows
                    header = csv_rows[0]
                    data_rows = csv_rows[1:]
                    
                    rows_processed = len(data_rows)
                    rows_imported = 0
                    import_errors = []
                    import_output = ""
                    
                    # Check if the header has the expected columns
                    expected_columns = ['id', 'name', 'email', 'department']
                    if len(header) >= len(expected_columns) and all(col.lower() == expected_columns[i].lower() for i, col in enumerate(header[:len(expected_columns)])):
                        # Process each row
                        for i, row in enumerate(data_rows):
                            if len(row) >= len(expected_columns):
                                # Extract values
                                id_val = row[0]
                                name_val = row[1]
                                email_val = row[2]
                                department_val = row[3]
                                
                                # Check for SQL injection patterns
                                sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]
                                
                                # Check if any SQL injection pattern is in the input
                                for pattern in sqli_patterns:
                                    if (pattern in id_val or pattern in name_val or pattern in email_val or pattern in department_val):
                                        # SQL injection detected!
                                        sqli_detected = True
                                        
                                        # Simulate SQL error
                                        import_output += f"SQL Error in row {i+1}: Syntax error in SQL statement\n"
                                        import_output += f"Attempted query: INSERT INTO employees (id, name, email, department) VALUES ('{id_val}', '{name_val}', '{email_val}', '{department_val}')\n\n"
                                        
                                        # Add the flag to the output
                                        import_output += "Unexpected query result:\n"
                                        import_output += "id | flag\n"
                                        import_output += "---+-----\n"
                                        import_output += f"1  | R00T{{f1l3_upl04d_sql1_1nj3ct10n_pwn3d}}\n"
                                        
                                        import_errors.append(f"Error in row {i+1}: SQL syntax error")
                                        
                                        # Mark challenge as completed
                                        challenge = Challenge.query.filter_by(name="SQL Injection via File Upload").first()
                                        if challenge:
                                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                            if challenge.id not in completed_ids:
                                                update_user_progress(machine_id, challenge.id, challenge.points)
                                        break
                                
                                if not sqli_detected:
                                    # Simulate successful import
                                    import_output += f"Imported row {i+1}: ID={id_val}, Name={name_val}, Email={email_val}, Department={department_val}\n"
                                    rows_imported += 1
                            else:
                                import_errors.append(f"Error in row {i+1}: Insufficient columns")
                        
                        if rows_imported == rows_processed:
                            import_status = "Complete"
                        elif rows_imported > 0:
                            import_status = "Partial"
                        else:
                            import_status = "Failed"
                    else:
                        error = "Invalid CSV format. Expected columns: id, name, email, department"
                else:
                    error = "Empty CSV file"
                
                upload_success = True
                
            except Exception as e:
                error = f"Error processing CSV: {str(e)}"
        else:
            error = "No CSV content provided"
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection via File Upload").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level19.html', flag=flag, sqli_detected=sqli_detected,
                          csv_content=csv_content, csv_preview=csv_preview, upload_success=upload_success,
                          rows_processed=rows_processed, rows_imported=rows_imported,
                          import_status=import_status, import_errors=import_errors,
                          import_output=import_output, error=error)
