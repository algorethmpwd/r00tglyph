# R00tGlyph Flag Gating Pattern for Challenge Routes

## Problem
Flags should **only** be shown when a user has successfully solved a challenge (per the `.globalrules`).

## Implementation Steps

1. **Track Completed Challenges**
   - Each LocalUser has a `completed_challenges` list (JSON).
   - When a user solves a challenge, add that challenge's ID to the list.

2. **Show Flag Only if Completed**
   - When rendering a challenge page, show the flag **only** if the challenge is marked as completed for the user.

3. **Pseudo-Example for a Challenge Route**

```python
@app.route('/xss/levelN', methods=['GET', 'POST'])
def xss_levelN():
    machine_id = get_machine_id()
    user = get_local_user()
    challenge = Challenge.query.filter_by(name="...").first()
    flag = None

    # Get this user's completed challenges
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []

    # Step 1: Detect challenge solve condition (custom logic here)
    if challenge and [SOLVE_CONDITION_DETECTED]:
        if challenge.id not in completed_ids:
            update_user_progress(machine_id, challenge.id, challenge.points)
            completed_ids.append(challenge.id)
        # Optionally flash a "solved!" message

    # Step 2: Show flag only if solved
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_levelN.html', ..., flag=flag)
```

**Replace `[SOLVE_CONDITION_DETECTED]`** with logic specific to the challenge, i.e. when XSS is actually performed or code is successfully exploited.

## To Fix Your Platform

- Update every challenge route (`/xss/levelN`, etc.) to implement this gating pattern.
- Ensure `update_user_progress` is ONLY called when the user legitimately solves the challenge.
- Never render the flag unless the user's `completed_challenges` includes the current challenge ID.