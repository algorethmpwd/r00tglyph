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

from app.services.backup_service import BackupService
from app.services.database_service import DatabaseService

from app import create_app, db


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
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║  ____   ___   ___  _    ____  _            _                  ║
║ |  _ \ / _ \ / _ \| |_ / ___|| |_   _ _ __ | |__                ║
║ | |_) | | | | | | | __| |  _| | | | | '_ \| '_ \               ║
║ |  _ <| |_| | |_| | |_| |_| | | |_| | |_) | | | |              ║
║ |_| \_\\___/ \___/ \__|\____|_|\__, | .__/|_| |_|              ║
║                                |___/|_|                       ║
║                                                               ║
║        Advanced Web Security Training Platform v2.0          ║
║                                                               ║
║  115+ Challenges | Real-world Scenarios | Professional Tools ║
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
    --port PORT         Port to bind to (default: 5000)
    --workers N         Number of worker processes (production only)

DATABASE MANAGEMENT:
    --init-db           Initialize the database with default data
    --reset-db          Reset database to clean state (WARNING: destroys all data)
    --migrate           Run database migrations
    --upgrade-db        Upgrade database schema to latest version

BACKUP & RECOVERY:
    --backup            Create backup of user data
    --restore           Restore user data from latest backup
    --list-backups      List available backups

UPDATE & MAINTENANCE:
    --update            Update R00tGlyph to latest version
    --check-health      Check system health and dependencies
    --version           Show version information

EXAMPLES:
    python run.py --dev                    # Run in development mode
    python run.py --host 0.0.0.0 --port 8080  # Run on all interfaces, port 8080
    python run.py --init-db                # Initialize fresh database
    python run.py --backup                 # Create data backup
    python run.py --update                 # Update to latest version

ENVIRONMENT VARIABLES:
    FLASK_ENV           Set to 'development' or 'production'
    SECRET_KEY          Application secret key (required for production)
    DATABASE_URL        Database connection URL
    REDIS_URL           Redis connection URL for caching

For more information, visit: https://github.com/algorethmpwd/R00tGlyph
"""
    print(help_text)


def handle_database_commands(args):
    """Handle database-related commands"""
    app = create_app()

    with app.app_context():
        db_service = DatabaseService()

        if args.init_db:
            print("🗄️  Initializing database...")
            db.create_all()
            db_service.initialize_challenges()
            db_service.create_admin_user()
            print("✅ Database initialized successfully!")
            return True

        elif args.reset_db:
            confirmation = input(
                "⚠️  This will destroy all data! Type 'CONFIRM' to proceed: "
            )
            if confirmation == "CONFIRM":
                print("🗄️  Resetting database...")
                db_service.reset_database()
                print("✅ Database reset completed!")
            else:
                print("❌ Database reset cancelled.")
            return True

        elif args.migrate:
            print("🗄️  Running database migrations...")
            try:
                from flask_migrate import upgrade

                upgrade()
                print("✅ Database migrations completed!")
            except ImportError:
                print("❌ Flask-Migrate not installed. Run: pip install Flask-Migrate")
            return True

        elif args.upgrade_db:
            print("🗄️  Upgrading database schema...")
            db_service.upgrade_schema()
            print("✅ Database schema upgraded!")
            return True

    return False


def handle_backup_commands(args):
    """Handle backup and restore commands"""
    backup_service = BackupService()

    if args.backup:
        print("💾 Creating backup...")
        backup_path = backup_service.create_backup()
        if backup_path:
            print(f"✅ Backup created: {backup_path}")
        else:
            print("❌ Backup failed!")
        return True

    elif args.restore:
        print("📥 Restoring from backup...")
        if backup_service.restore_latest():
            print("✅ Data restored successfully!")
        else:
            print("❌ Restore failed!")
        return True

    elif args.list_backups:
        print("📋 Available backups:")
        backups = backup_service.list_backups()
        if backups:
            for i, backup in enumerate(backups, 1):
                print(
                    f"  {i}. {backup['filename']} ({backup['size']}) - {backup['created']}"
                )
        else:
            print("  No backups found.")
        return True

    return False


def handle_maintenance_commands(args):
    """Handle maintenance and update commands"""
    if args.update:
        print("🔄 Updating R00tGlyph...")
        try:
            import subprocess

            import git

            repo = git.Repo(project_root)
            origin = repo.remotes.origin

            print("📥 Fetching latest changes...")
            origin.fetch()

            print("💾 Creating backup before update...")
            backup_service = BackupService()
            backup_path = backup_service.create_backup()

            print("🔄 Pulling latest code...")
            origin.pull()

            print("📦 Installing dependencies...")
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
            )

            print("🗄️  Running database migrations...")
            app = create_app()
            with app.app_context():
                try:
                    from flask_migrate import upgrade

                    upgrade()
                except ImportError:
                    pass

            print("✅ Update completed successfully!")
            print(f"💾 Backup saved at: {backup_path}")

        except Exception as e:
            print(f"❌ Update failed: {str(e)}")
        return True

    elif args.check_health:
        print("🔍 Checking system health...")

        # Check Python version
        python_version = sys.version_info
        print(
            f"🐍 Python: {python_version.major}.{python_version.minor}.{python_version.micro}"
        )

        # Check dependencies
        try:
            import flask

            print(f"🌶️  Flask: {flask.__version__}")
        except ImportError:
            print("❌ Flask not installed")

        try:
            import redis

            r = redis.Redis(host="localhost", port=6379, decode_responses=True)
            r.ping()
            print("🔴 Redis: Connected")
        except:
            print("⚠️  Redis: Not available (optional)")

        # Check database
        try:
            app = create_app()
            with app.app_context():
                db.engine.execute("SELECT 1")
                print("🗄️  Database: Connected")
        except Exception as e:
            print(f"❌ Database: Connection failed - {str(e)}")

        # Check disk space
        import shutil

        total, used, free = shutil.disk_usage(project_root)
        free_gb = free // (1024**3)
        print(f"💾 Disk Space: {free_gb} GB free")

        print("✅ Health check completed!")
        return True

    elif args.version:
        print("📋 Version Information:")
        print(f"  R00tGlyph: 2.0.0")
        print(f"  Python: {sys.version}")
        print(f"  Platform: {sys.platform}")
        try:
            import flask

            print(f"  Flask: {flask.__version__}")
        except ImportError:
            pass
        return True

    return False


def run_development_server(app, host="127.0.0.1", port=5000):
    """Run development server with hot reload"""
    print(f"🚀 Starting development server on http://{host}:{port}")
    print("📝 Debug mode: ON")
    print("🔄 Auto-reload: ON")
    print("⚠️  For production, use: gunicorn -w 4 run:app")
    print("\n" + "=" * 60)

    app.run(host=host, port=port, debug=True, threaded=True, use_reloader=True)


def run_production_server(app, host="127.0.0.1", port=5000, workers=4):
    """Run production server with Gunicorn"""
    try:
        import gunicorn.app.wsgiapp as wsgi

        sys.argv = [
            "gunicorn",
            "--bind",
            f"{host}:{port}",
            "--workers",
            str(workers),
            "--worker-class",
            "eventlet",
            "--worker-connections",
            "1000",
            "--timeout",
            "120",
            "--keepalive",
            "2",
            "--max-requests",
            "1000",
            "--max-requests-jitter",
            "100",
            "--preload",
            "--access-logfile",
            "-",
            "--error-logfile",
            "-",
            "run:app",
        ]

        print(f"🚀 Starting production server on http://{host}:{port}")
        print(f"👥 Workers: {workers}")
        print("🔒 Production mode: ON")
        print("\n" + "=" * 60)

        wsgi.run()

    except ImportError:
        print("❌ Gunicorn not installed. Install with: pip install gunicorn")
        print("🔄 Falling back to development server...")
        run_development_server(app, host, port)


def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description="R00tGlyph - Advanced Web Security Training Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Server options
    parser.add_argument("--dev", action="store_true", help="Run in development mode")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    parser.add_argument(
        "--workers", type=int, default=4, help="Number of workers (production)"
    )

    # Database commands
    parser.add_argument("--init-db", action="store_true", help="Initialize database")
    parser.add_argument("--reset-db", action="store_true", help="Reset database")
    parser.add_argument("--migrate", action="store_true", help="Run migrations")
    parser.add_argument("--upgrade-db", action="store_true", help="Upgrade database")

    # Backup commands
    parser.add_argument("--backup", action="store_true", help="Create backup")
    parser.add_argument("--restore", action="store_true", help="Restore backup")
    parser.add_argument("--list-backups", action="store_true", help="List backups")

    # Maintenance commands
    parser.add_argument("--update", action="store_true", help="Update R00tGlyph")
    parser.add_argument(
        "--check-health", action="store_true", help="Check system health"
    )
    parser.add_argument("--version", action="store_true", help="Show version")

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

    # Handle commands that don't require server startup
    if handle_database_commands(args):
        return

    if handle_backup_commands(args):
        return

    if handle_maintenance_commands(args):
        return

    # Create Flask application
    try:
        config_name = "development" if args.dev else "production"
        app = create_app(config_name)

        # Set Flask app for gunicorn
        globals()["app"] = app

        # Run server
        if args.dev or os.environ.get("FLASK_ENV") == "development":
            run_development_server(app, args.host, args.port)
        else:
            run_production_server(app, args.host, args.port, args.workers)

    except KeyboardInterrupt:
        print("\n👋 Shutting down R00tGlyph...")
    except Exception as e:
        print(f"❌ Failed to start R00tGlyph: {str(e)}")
        logging.exception("Application startup failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
