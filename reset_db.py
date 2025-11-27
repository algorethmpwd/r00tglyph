#!/usr/bin/env python
"""
Database reset script for R00tGlyph
This will drop all tables and recreate them with the new schema
"""

from app import app, db

def reset_database():
    with app.app_context():
        print("Dropping all tables...")
        db.drop_all()
        print("Creating all tables with new schema...")
        db.create_all()
        print("✅ Database reset complete!")
        print("The new 'profile_picture' column has been added to LocalUser model.")

if __name__ == '__main__':
    reset_database()
