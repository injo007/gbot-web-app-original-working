#!/bin/bash

# Script to clean up all the unnecessary and unused files
# now that we have the consolidated install_gbot.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print header
echo -e "${BLUE}=== Cleaning up unused files ===${NC}"

# List of files to be removed
FILES_TO_REMOVE=(
    "setup_complete.sh"
    "setup_complete_enhanced.sh"
    "optimize_frontend_build.sh"
    "verify_frontend_deployment.sh"
    "FRONTEND_DEPLOYMENT_GUIDE.md"
    "QUICKSTART_UBUNTU22.md"
    "gunicorn.fixed.service"
    "FIX_GUNICORN_SERVICE.md"
    "gunicorn.simple.service"
    "SIMPLE_SERVICE_FIX.md"
    "gunicorn.basic.service"
    "BASIC_SERVICE_FIX.md"
    "nginx.simplified.conf"
)

# Remove each file
for file in "${FILES_TO_REMOVE[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${YELLOW}Removing${NC} $file"
        rm -f "$file"
        echo -e "${GREEN}Removed${NC} $file"
    else
        echo -e "${YELLOW}File not found:${NC} $file"
    fi
done

echo -e "\n${GREEN}Cleanup complete!${NC}"
echo -e "${BLUE}The consolidated installation script install_gbot.sh and INSTALLATION.md are the only files you need now.${NC}"
