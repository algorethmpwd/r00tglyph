#!/usr/bin/env python3
"""
R00tGlyph - Advanced Web Security Training Platform
Main Application Entry Point

This is the main entry point for the R00tGlyph application.
It handles application initialization, configuration, and startup.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))


def setup_logging(debug_mode=False):
    """Setup logging configuration"""
    log_level = logging.DEBUG if debug_mode else logging.INFO

    # Create logs directory if it doesn't exist
    logs_dir = project_root / "logs"
    logs_dir.mkdir(exist_ok=True)

    # Configure logging
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(logs_dir / "rootglyph.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def print_banner():
    """Print R00tGlyph banner"""
    banner = r"""
╔═══════════════════════════════════════════════════════════════╗
║  ____   ___   ___  _    ____  _            _                  ║
║ |  _ \ / _ \ / _ \| |_ / ___|| |_   _ _ __ | |__              ║
║ | |_) | | | | | | | __| |  _ | | | | | '_ \| '_ \             ║
║ |  _ <| |_| | |_| | |_| |_| || | |_| | |_) | | | |            ║
║ |_| \_\\___/ \___/ \__|\____||_|\__, | .__/|_| |_|            ║
║                                 |___/|_|                      ║
║                                                               ║
║        Advanced Web Security Training Platform v2.0           ║
║                                                               ║
║  188 Challenges | Teams | Admin Panel | Hints & Solutions    ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def show_help():
    """Show detailed help information"""
    help_text = """
R00tGlyph - Advanced Web Security Training Platform

USAGE:
    python run.py [OPTIONS]

OPTIONS:
    -h, --help          Show this help message
    --dev               Run in development mode with debug enabled
    --host HOST         Host to bind to (default: 127.0.0.1)
    -p, --port PORT     Port to bind to (default: 5000)

DATABASE MANAGEMENT:
    --reset-db          Reset database to clean state (WARNING: destroys all data)

BACKUP & RECOVERY:
    --backup            Create backup of user data
    --restore           Restore user data from latest backup

EXAMPLES:
    python run.py --dev                    # Run in development mode
    python run.py --host 0.0.0.0 --port 8080  # Run on all interfaces, port 8080
    python run.py --backup                 # Create data backup

For more information, visit: https://github.com/algorethmpwd/R00tGlyph
"""
    print(help_text)


def run_development_server(app, host="127.0.0.1", port=5000):
    """Run development server with hot reload"""
    print(f"🚀 Starting development server on http://{host}:{port}")
    print("📝 Debug mode: ON")
    print("🔄 Auto-reload: ON")
    print("⚠️  For production, use: gunicorn -w 4 'app:app'")
    print("\n" + "=" * 60)

    app.run(host=host, port=port, debug=True, threaded=True, use_reloader=True)


def run_production_server(app, host="127.0.0.1", port=5000):
    """Run production server"""
    print(f"🚀 Starting server on http://{host}:{port}")
    print("🔒 Production mode: ON")
    print("\n" + "=" * 60)

    app.run(host=host, port=port, debug=False, threaded=True)


def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description="R00tGlyph - Advanced Web Security Training Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Server options
    parser.add_argument("--dev", action="store_true", help="Run in development mode")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("-p", "--port", type=int, default=5000, help="Port to bind to")

    # Database commands
    parser.add_argument("--reset-db", action="store_true", help="Reset database")

    # Backup commands
    parser.add_argument("--backup", action="store_true", help="Create backup")
    parser.add_argument("--restore", action="store_true", help="Restore backup")

    # Help
    parser.add_argument(
        "--help-detailed", action="store_true", help="Show detailed help"
    )

    args = parser.parse_args()

    # Show detailed help if requested
    if args.help_detailed:
        show_help()
        return

    # Setup logging
    setup_logging(debug_mode=args.dev)

    # Print banner
    print_banner()

    # Import the app from app.py (the monolithic working version)
    try:
        from app import app, db, reset_database
    except ImportError as e:
        print(f"❌ Failed to import application: {str(e)}")
        sys.exit(1)

    # Handle database reset
    if args.reset_db:
        confirmation = input(
            "⚠️  This will destroy all data! Type 'CONFIRM' to proceed: "
        )
        if confirmation == "CONFIRM":
            print("🗄️  Resetting database...")
            reset_database()
            print("✅ Database reset completed!")
        else:
            print("❌ Database reset cancelled.")
        return

    # Handle backup command
    if args.backup:
        import shutil
        from datetime import datetime

        backup_dir = "backup"
        db_file = "instance/r00tglyph.db"

        os.makedirs(backup_dir, exist_ok=True)

        if os.path.exists(db_file):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{backup_dir}/r00tglyph_{timestamp}.db.bak"
            shutil.copy2(db_file, backup_file)
            shutil.copy2(db_file, f"{backup_dir}/r00tglyph.db.bak")
            print(f"✅ Backup created: {backup_file}")
        else:
            print("❌ No database file found to backup.")
        return

    # Handle restore command
    if args.restore:
        import shutil

        backup_file = "backup/r00tglyph.db.bak"
        db_file = "instance/r00tglyph.db"

        if os.path.exists(backup_file):
            os.makedirs("instance", exist_ok=True)
            shutil.copy2(backup_file, db_file)
            print("✅ Data restored successfully!")
        else:
            print("❌ No backup file found to restore.")
        return

    # Run server
    try:
        if args.dev or os.environ.get("FLASK_ENV") == "development":
            run_development_server(app, args.host, args.port)
        else:
            run_production_server(app, args.host, args.port)

    except KeyboardInterrupt:
        print("\n👋 Shutting down R00tGlyph...")
    except Exception as e:
        print(f"❌ Failed to start R00tGlyph: {str(e)}")
        logging.exception("Application startup failed")
        sys.exit(1)


# Export app for gunicorn
try:
    from app import app
except ImportError:
    app = None

if __name__ == "__main__":
    main()
