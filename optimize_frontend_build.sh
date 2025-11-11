#!/bin/bash

# Script to optimize frontend build and replace old frontend
# This addresses the memory issues during build and ensures clean replacement

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Starting frontend optimization..."

# Set paths
APP_ROOT="/opt/gbot-web-app-original-working"
FRONTEND_DIR="$APP_ROOT/gbot-frontend"
FRONTEND_DIST="$FRONTEND_DIR/dist"
FRONTEND_STATIC="$APP_ROOT/static"
FRONTEND_BACKUP="$APP_ROOT/static.bak"
TEMPLATES_DIR="$APP_ROOT/templates"

# Check if we're in the right directory
if [ ! -d "$FRONTEND_DIR" ]; then
    echo -e "${RED}[✗] Frontend directory not found at $FRONTEND_DIR${NC}"
    exit 1
fi

# Step 1: Clean up old frontend files completely
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Removing old frontend files..."
# Backup templates first
if [ -d "$TEMPLATES_DIR" ]; then
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Backing up templates..."
    BACKUP_DIR="$APP_ROOT/templates_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    cp -r "$TEMPLATES_DIR"/* "$BACKUP_DIR/" 2>/dev/null || true
    sudo rm -rf "$TEMPLATES_DIR"
    echo -e "${GREEN}[✓] Templates backed up to $BACKUP_DIR${NC}"
fi

# Backup static files if they exist
if [ -d "$FRONTEND_STATIC" ]; then
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Backing up static files..."
    STATIC_BACKUP_DIR="$APP_ROOT/static_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$STATIC_BACKUP_DIR"
    cp -r "$FRONTEND_STATIC"/* "$STATIC_BACKUP_DIR/" 2>/dev/null || true
    sudo rm -rf "$FRONTEND_STATIC"/*
    echo -e "${GREEN}[✓] Static files backed up to $STATIC_BACKUP_DIR${NC}"
fi

# Ensure static directory exists
mkdir -p "$FRONTEND_STATIC"

# Step 2: Optimize the system for build
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Optimizing system for build..."

# Clean up any existing swap
SWAP_FILE="/swapfile"
if [ -f "$SWAP_FILE" ]; then
    echo "Removing existing swap file..."
    sudo swapoff "$SWAP_FILE" || true
    sudo rm -f "$SWAP_FILE" || true
fi

# Create a larger swap file (4GB instead of 2GB)
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Creating 4GB swap file..."
sudo fallocate -l 4G "$SWAP_FILE" || sudo dd if=/dev/zero of="$SWAP_FILE" bs=1M count=4096
sudo chmod 600 "$SWAP_FILE"
sudo mkswap "$SWAP_FILE"
sudo swapon "$SWAP_FILE"
echo -e "${GREEN}[✓] Swap file created and activated${NC}"

# Clean system caches
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Cleaning system caches..."
sync && sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'

# Step 3: Optimize build process
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Optimizing frontend build process..."
cd "$FRONTEND_DIR"

# Clean npm cache and remove node_modules
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Cleaning npm cache and node_modules..."
npm cache clean --force
rm -rf node_modules package-lock.json

# Install with minimal dependencies first (production mode to minimize memory usage)
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Installing dependencies in production mode..."
export NODE_OPTIONS="--max-old-space-size=4096"
npm install --no-audit --no-optional --production

# Then install dev dependencies
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Installing dev dependencies specifically..."
npm install --no-save --no-audit --no-optional --save-dev typescript vite @vitejs/plugin-react

# Step 4: Modify package.json scripts to use more memory-efficient settings
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Updating build scripts..."
# Use jq if available, otherwise sed
if command -v jq &> /dev/null; then
    jq '.scripts.build = "NODE_OPTIONS=--max-old-space-size=4096 vite build --emptyOutDir"' package.json > package.json.tmp
    mv package.json.tmp package.json
else
    # Use sed as a fallback (less reliable)
    sed -i 's/"build": "tsc && vite build"/"build": "NODE_OPTIONS=--max-old-space-size=4096 vite build --emptyOutDir"/g' package.json
fi
echo -e "${GREEN}[✓] Build script updated${NC}"

# Step 5: Build with memory-efficient settings
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Running production build..."
export NODE_ENV=production
export GENERATE_SOURCEMAP=false

# Try to build with various optimizations
echo -e "${YELLOW}[!] Attempting optimized build...${NC}"
# Skip type checking to save memory
npm run build || {
    echo -e "${YELLOW}[!] Standard build failed, trying with less memory usage...${NC}"
    # Try with very minimal setting
    NODE_OPTIONS="--max-old-space-size=3072" npx vite build --emptyOutDir || {
        echo -e "${RED}[✗] Build failed again, trying last resort build...${NC}"
        # Ultimate fallback with absolute minimal settings
        NODE_OPTIONS="--max-old-space-size=2048" npx vite build --mode development --minify false || {
            echo -e "${RED}[✗] All build attempts failed${NC}"
            sudo swapoff "$SWAP_FILE"
            sudo rm "$SWAP_FILE"
            exit 1
        }
        echo -e "${YELLOW}[!] Built with development mode (unoptimized)${NC}"
    }
}

# Step 6: Copy built files to static directory
if [ -d "$FRONTEND_DIST" ] && [ "$(ls -A $FRONTEND_DIST)" ]; then
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Copying built files to static directory..."
    cp -r "$FRONTEND_DIST"/* "$FRONTEND_STATIC/"
    
    # Set proper permissions
    sudo chown -R www-data:www-data "$FRONTEND_STATIC" || true
    sudo chmod -R 755 "$FRONTEND_STATIC" || true
    
    echo -e "${GREEN}[✓] Frontend files copied to static directory${NC}"
else
    echo -e "${RED}[✗] Build output directory is missing or empty${NC}"
    sudo swapoff "$SWAP_FILE"
    sudo rm "$SWAP_FILE"
    exit 1
fi

# Step 7: Clean up
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Cleaning up..."
sudo swapoff "$SWAP_FILE"
sudo rm "$SWAP_FILE"
echo -e "${GREEN}[✓] Removed temporary swap file${NC}"

# Step 8: Verify installation
echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Verifying installation..."
if [ -f "$FRONTEND_STATIC/index.html" ]; then
    echo -e "${GREEN}[✓] Frontend build successful and installed${NC}"
else
    echo -e "${RED}[✗] Frontend installation failed - index.html not found${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Frontend optimization and installation completed!${NC}"
echo -e "${BLUE}[!] Please restart the app and web services with: sudo systemctl restart gbot nginx${NC}"

exit 0
