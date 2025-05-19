#!/bin/bash
# Script to handle the update issue and reorganize the project

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if git is installed
if ! command_exists git; then
    echo "Error: git is not installed. Please install git and try again."
    exit 1
fi

# Check if python is installed
if ! command_exists python; then
    echo "Error: python is not installed. Please install python and try again."
    exit 1
fi

# Function to handle errors
handle_error() {
    echo "Error: $1"
    exit 1
}

echo "🔄 Starting update and reorganization process..."

# Step 1: Backup the database
echo "📦 Backing up the database..."
python app.py --backup || handle_error "Failed to backup the database"
echo "✅ Database backup complete"

# Step 2: Stash local changes
echo "📝 Stashing local changes..."
git stash || handle_error "Failed to stash local changes"
echo "✅ Local changes stashed"

# Step 3: Update from GitHub
echo "🔄 Updating from GitHub..."
python app.py --update || handle_error "Failed to update from GitHub"
echo "✅ Update from GitHub complete"

# Step 4: Apply stashed changes
echo "📝 Applying stashed changes..."
git stash pop || echo "⚠️ Warning: Failed to apply stashed changes. This may be because there were conflicts."
echo "✅ Stashed changes applied (or attempted to apply)"

# Step 5: Run the reorganization script
echo "🔄 Reorganizing the project..."
python reorganize_project.py || handle_error "Failed to reorganize the project"
echo "✅ Project reorganization complete"

echo "🎉 Update and reorganization process completed successfully!"
echo ""
echo "Next steps:"
echo "1. Review the changes and make sure everything is in the right place"
echo "2. Update imports in app.py to use the new module structure"
echo "3. Test the application to ensure everything still works"
