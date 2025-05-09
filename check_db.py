#!/usr/bin/env python3
from app import app, db, Challenge

with app.app_context():
    challenges = Challenge.query.all()
    for c in challenges:
        print(f"{c.id}: {c.name} - Active: {c.active}")
