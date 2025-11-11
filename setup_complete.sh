#!/bin/bash

# GBot Web Application - COMPLETE Installation & Setup Script
# This is the ONLY installation script you need - handles everything
# Features: Root execution, Reinstallation, All modules, Production deployment, SSL, Monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="GBot Web Application"
LOG_FILE="$SCRIPT_DIR/setup.log"

# Frontend configuration
if [[ "$SCRIPT_DIR" == */gbot-frontend ]]; then
    # We're inside the frontend directory
    FRONTEND_DIR="$SCRIPT_DIR"
    PARENT_DIR="$(dirname "$SCRIPT_DIR")"
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    FRONTEND_STATIC="$PARENT_DIR/static"
    FRONTEND_BACKUP="$PARENT_DIR/static.bak"
elif [[ "$SCRIPT_DIR" == */gbot-web-app* ]]; then
    # We're in the main app directory
    FRONTEND_DIR="$SCRIPT_DIR/gbot-frontend"
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    FRONTEND_STATIC="$SCRIPT_DIR/static"
    FRONTEND_BACKUP="$SCRIPT_DIR/static.bak"
else
    # Fallback for other locations
    FRONTEND_DIR="$(dirname "$SCRIPT_DIR")/gbot-frontend"
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    FRONTEND_STATIC="$(dirname "$SCRIPT_DIR")/static"
    FRONTEND_BACKUP="$(dirname "$SCRIPT_DIR")/static.bak"
fi

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" >> "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$LOG_FILE"
}

setup_frontend() {
    log "Setting up frontend..."

    # Increase system limits for the build process
    ulimit -n 65535 2>/dev/null || true
    sudo sysctl -w vm.max_map_count=262144 2>/dev/null || true
    sudo sysctl -w fs.file-max=65535 2>/dev/null || true

    # Install Node.js and npm if not present
    if ! command -v node &> /dev/null; then
        log "Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
        sudo apt-get update
        sudo apt-get install -y nodejs build-essential
    fi

    # Verify Node.js installation
    if ! command -v node &> /dev/null; then
        log_error "Node.js installation failed"
        exit 1
    fi

    # Create frontend directory structure if needed
    log "Setting up directory structure..."
    if [ ! -d "$FRONTEND_DIR/src" ]; then
        mkdir -p "$FRONTEND_DIR"/{src,public,dist,node_modules}
        mkdir -p "$FRONTEND_DIR/src"/{components,pages,store,theme,api,layouts}
        log_success "Directory structure created"
    else
        log "Using existing directory structure"
    fi

    # Backup existing static files
    if [ -d "$FRONTEND_STATIC" ]; then
        log "Backing up existing static files..."
        mv "$FRONTEND_STATIC" "$FRONTEND_BACKUP"
    fi

    # Create static directory
    mkdir -p "$FRONTEND_STATIC"

    # Check if we're in the correct directory structure
    if [[ "$SCRIPT_DIR" == */gbot-frontend ]]; then
        log "Already in frontend directory"
    elif [[ "$SCRIPT_DIR" == */gbot-web-app* ]]; then
        log "In main app directory"
        if [ ! -d "$FRONTEND_DIR" ]; then
            mkdir -p "$FRONTEND_DIR"
        fi
    else
        log "In external directory"
        if [ ! -d "$FRONTEND_DIR" ]; then
            mkdir -p "$FRONTEND_DIR"
        fi
    fi

    # No need to copy files if we're already in the right place
    if [ "$SCRIPT_DIR" != "$FRONTEND_DIR" ] && [ -d "$SCRIPT_DIR/gbot-frontend" ]; then
        log "Copying frontend files from current directory..."
        rsync -a --delete "$SCRIPT_DIR/gbot-frontend/" "$FRONTEND_DIR/" || {
            log_error "Failed to copy frontend files"
            exit 1
        }
    fi
    
    log_success "Frontend directory setup completed"

    # Verify critical files
    log "Verifying frontend files..."
    REQUIRED_FILES=(
        "package.json"
        "tsconfig.json"
        "vite.config.ts"
        "src/main.tsx"
        "src/App.tsx"
        "index.html"
    )
    
    for file in "${REQUIRED_FILES[@]}"; do
        if [ ! -f "$FRONTEND_DIR/$file" ]; then
            log_error "Missing required file: $file"
            exit 1
        fi
    done

    # Build frontend
    log "Building frontend..."
    cd "$FRONTEND_DIR"

    # Clear npm cache and remove node_modules
    log "Cleaning npm cache..."
    npm cache clean --force
    rm -rf node_modules package-lock.json dist

    # Install dependencies with increased memory limit and error handling
    log "Installing frontend dependencies..."
    export NODE_OPTIONS="--max-old-space-size=2048"
    
    # Create temporary swap space to handle memory-intensive operations
    SWAP_FILE="/swapfile"
    if [ ! -f "$SWAP_FILE" ]; then
        log "Creating temporary swap space..."
        sudo fallocate -l 2G "$SWAP_FILE" || sudo dd if=/dev/zero of="$SWAP_FILE" bs=1M count=2048
        sudo chmod 600 "$SWAP_FILE"
        sudo mkswap "$SWAP_FILE"
        sudo swapon "$SWAP_FILE"
    fi

    # Install dependencies in chunks with retry logic
    install_with_retry() {
        local max_retries=3
        local retry_count=0
        local packages="$1"
        local desc="$2"

        while [ $retry_count -lt $max_retries ]; do
            log "Installing $desc (attempt $((retry_count + 1))/$max_retries)..."
            if npm install --no-audit --no-optional --production=false $packages; then
                return 0
            fi
            retry_count=$((retry_count + 1))
            log_warning "Installation failed, retrying in 5 seconds..."
            sleep 5
        done
        return 1
    }

    # Core dependencies
    if ! install_with_retry "react react-dom @reduxjs/toolkit react-redux react-router-dom axios" "core dependencies"; then
        log_error "Failed to install core dependencies"
        sudo swapoff "$SWAP_FILE"
        sudo rm "$SWAP_FILE"
        exit 1
    fi

    # UI dependencies
    if ! install_with_retry "@emotion/react @emotion/styled framer-motion" "UI dependencies"; then
        log_error "Failed to install UI dependencies"
        sudo swapoff "$SWAP_FILE"
        sudo rm "$SWAP_FILE"
        exit 1
    fi

    # Dev dependencies
    if ! install_with_retry "--save-dev typescript @types/react @types/react-dom @vitejs/plugin-react vite" "dev dependencies"; then
        log_error "Failed to install dev dependencies"
        sudo swapoff "$SWAP_FILE"
        sudo rm "$SWAP_FILE"
        exit 1
    fi

    # Verify critical dependencies
    log "Verifying dependencies..."
    if ! npm list react >/dev/null 2>&1 || ! npm list vite >/dev/null 2>&1; then
        log_error "Critical dependencies are missing"
        sudo swapoff "$SWAP_FILE"
        sudo rm "$SWAP_FILE"
        exit 1
    fi

    # Remove temporary swap
    sudo swapoff "$SWAP_FILE"
    sudo rm "$SWAP_FILE"

    # Build the application with production optimization
    log "Building production bundle..."
    export NODE_OPTIONS="--max-old-space-size=2048"
    GENERATE_SOURCEMAP=false npm run build || {
        log_error "Failed to build frontend"
        exit 1
    }

    # Verify build
    if [ ! -d "$FRONTEND_DIST" ]; then
        log_error "Frontend build failed"
        # Restore backup if build fails
        if [ -d "$FRONTEND_BACKUP" ]; then
            mv "$FRONTEND_BACKUP" "$FRONTEND_STATIC"
        fi
        exit 1
    fi

    # Update Flask app to serve frontend
    log "Updating Flask app to serve frontend..."
    if ! grep -q "send_from_directory" "$SCRIPT_DIR/app.py"; then
        cat >> "$SCRIPT_DIR/app.py" << 'EOF'

# Frontend serving routes
import os
from flask import send_from_directory

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')
EOF
    fi

    # Copy new frontend files to static directory
    log "Copying frontend files..."
    if [ -d "$FRONTEND_DIST" ]; then
        cp -r "$FRONTEND_DIST"/* "$FRONTEND_STATIC/"
        
        # Set proper permissions
        sudo chown -R www-data:www-data "$FRONTEND_STATIC"
        sudo chmod -R 755 "$FRONTEND_STATIC"

        # Verify critical files
        if [ -f "$FRONTEND_STATIC/index.html" ]; then
            log_success "Frontend files copied successfully"
        else
            log_error "Frontend build files are incomplete"
            # Restore backup if exists
            if [ -d "$FRONTEND_BACKUP" ]; then
                rm -rf "$FRONTEND_STATIC"
                mv "$FRONTEND_BACKUP" "$FRONTEND_STATIC"
                log_warning "Restored previous version from backup"
            fi
            exit 1
        fi

        # Clean up backup if everything succeeded
        if [ -d "$FRONTEND_BACKUP" ]; then
            rm -rf "$FRONTEND_BACKUP"
        fi

        # Clean up build artifacts
        log "Cleaning up build artifacts..."
        rm -rf node_modules
        npm cache clean --force

        log_success "Frontend setup completed"
    else
        log_error "Frontend build failed - dist directory not found"
        # Restore backup if exists
        if [ -d "$FRONTEND_BACKUP" ]; then
            rm -rf "$FRONTEND_STATIC"
            mv "$FRONTEND_BACKUP" "$FRONTEND_STATIC"
            log_warning "Restored previous version from backup"
        fi
        exit 1
    fi
}

update_nginx_config() {
    log "Updating Nginx configuration for frontend..."

    # Create new Nginx configuration
    cat > /tmp/gbot_nginx << EOF
server {
    listen 80;
    server_name _;

    root $FRONTEND_STATIC;
    index index.html;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://api.ipify.org;" always;

    # Frontend routes
    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache";
        expires 0;
    }

    # API proxy
    location /api/ {
        include proxy_params;
        proxy_pass http://unix:$SCRIPT_DIR/gbot.sock;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffer settings
        proxy_buffer_size 16k;
        proxy_buffers 4 32k;
        proxy_busy_buffers_size 64k;
    }

    # Static assets
    location /static {
        alias $FRONTEND_STATIC;
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Health check
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Favicon
    location = /favicon.ico {
        access_log off;
        log_not_found off;
    }

    # Robots.txt
    location = /robots.txt {
        access_log off;
        log_not_found off;
    }
}
EOF

    # Replace existing Nginx configuration
    sudo cp /tmp/gbot_nginx /etc/nginx/sites-available/gbot
    rm /tmp/gbot_nginx

    # Enable site if not already enabled
    if [ ! -L "/etc/nginx/sites-enabled/gbot" ]; then
        sudo ln -s /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/
    fi

    # Remove default site if it exists
    if [ -L "/etc/nginx/sites-enabled/default" ]; then
        sudo rm /etc/nginx/sites-enabled/default
    fi

    # Test and reload Nginx
    if sudo nginx -t; then
        sudo systemctl reload nginx
        log_success "Nginx configuration updated"
    else
        log_error "Nginx configuration test failed"
        exit 1
    fi
}

# Add frontend setup to the main installation function
run_complete_installation() {
    # ... (keep existing installation steps) ...

    # Add frontend setup
    setup_frontend

    # Update Nginx configuration
    update_nginx_config

    # Restart services
    sudo systemctl restart gbot
    sudo systemctl restart nginx

    # ... (keep rest of the function) ...
}

# Main function with frontend options
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -i|--install)
                INSTALL_MODE="complete"
                shift
                ;;
            -r|--reinstall)
                FORCE_REINSTALL=true
                INSTALL_MODE="complete"
                shift
                ;;
            --setup-frontend)
                setup_frontend
                update_nginx_config
                sudo systemctl restart gbot nginx
                verify_frontend_deployment
                exit 0
                ;;
            --update-frontend)
                setup_frontend
                update_nginx_config
                sudo systemctl restart gbot nginx
                verify_frontend_deployment
                exit 0
                ;;
            --fix-frontend)
                fix_frontend_issues
                exit 0
                ;;
            --verify-frontend)
                verify_frontend_deployment
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Run complete installation if no specific option is provided
    if [ "$INSTALL_MODE" = "complete" ]; then
        run_complete_installation
    else
        show_help
    fi
}

# Function to verify frontend deployment
verify_frontend_deployment() {
    log "Verifying frontend deployment..."

    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                FRONTEND DEPLOYMENT VERIFICATION             ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"

    # Check if static directory exists and has files
    if [ -d "$FRONTEND_STATIC" ] && [ "$(ls -A $FRONTEND_STATIC)" ]; then
        echo -e "✅ Static directory: ${GREEN}EXISTS AND NOT EMPTY${NC}"
    else
        echo -e "❌ Static directory: ${RED}MISSING OR EMPTY${NC}"
        return 1
    fi

    # Check if index.html exists
    if [ -f "$FRONTEND_STATIC/index.html" ]; then
        echo -e "✅ Index file: ${GREEN}EXISTS${NC}"
    else
        echo -e "❌ Index file: ${RED}MISSING${NC}"
        return 1
    fi

    # Check Nginx configuration
    echo -e "\n📋 Nginx Configuration:"
    if [ -f "/etc/nginx/sites-enabled/gbot" ]; then
        echo -e "✅ Nginx config: ${GREEN}ENABLED${NC}"
        if grep -q "try_files.*index.html" "/etc/nginx/sites-enabled/gbot"; then
            echo -e "✅ SPA routing: ${GREEN}CONFIGURED${NC}"
        else
            echo -e "❌ SPA routing: ${RED}MISCONFIGURED${NC}"
        fi
    else
        echo -e "❌ Nginx config: ${RED}MISSING${NC}"
        return 1
    fi

    # Check Flask route
    echo -e "\n📋 Flask Configuration:"
    if grep -q "send_from_directory.*index.html" "$SCRIPT_DIR/app.py"; then
        echo -e "✅ Flask route: ${GREEN}CONFIGURED${NC}"
    else
        echo -e "❌ Flask route: ${RED}MISSING${NC}"
        return 1
    fi

    # Test connection
    echo -e "\n📡 Connection Tests:"
    SERVER_IP=$(hostname -I | awk '{print $1}')

    # Test 1: Direct file access
    if curl -s -f "http://$SERVER_IP/index.html" > /dev/null; then
        echo -e "✅ Static files: ${GREEN}ACCESSIBLE${NC}"
    else
        echo -e "❌ Static files: ${RED}INACCESSIBLE${NC}"
    fi

    # Test 2: SPA routing
    if curl -s -f "http://$SERVER_IP/dashboard" > /dev/null; then
        echo -e "✅ SPA routing: ${GREEN}WORKING${NC}"
    else
        echo -e "❌ SPA routing: ${RED}FAILED${NC}"
    fi

    # Test 3: API proxy
    if curl -s -f "http://$SERVER_IP/api/health" > /dev/null; then
        echo -e "✅ API proxy: ${GREEN}WORKING${NC}"
    else
        echo -e "❌ API proxy: ${RED}FAILED${NC}"
    fi

    echo -e "\n🌐 Frontend URLs:"
    echo -e "   Main app: ${BLUE}http://$SERVER_IP${NC}"
    echo -e "   Health check: ${BLUE}http://$SERVER_IP/health${NC}"
    echo -e "   API test: ${BLUE}http://$SERVER_IP/api/health${NC}"

    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Function to fix frontend issues
fix_frontend_issues() {
    log "Fixing frontend deployment issues..."

    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                FIXING FRONTEND DEPLOYMENT                   ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"

    # Stop services
    sudo systemctl stop nginx
    sudo systemctl stop gbot

    # Backup current deployment
    BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    if [ -d "$FRONTEND_STATIC" ]; then
        mv "$FRONTEND_STATIC" "${FRONTEND_STATIC}_${BACKUP_TIMESTAMP}"
    fi

    # Rebuild frontend
    log "Rebuilding frontend..."
    setup_frontend

    # Reconfigure Nginx
    log "Reconfiguring Nginx..."
    update_nginx_config

    # Update Flask routes
    log "Updating Flask routes..."
    if ! grep -q "send_from_directory.*index.html" "$SCRIPT_DIR/app.py"; then
        cat >> "$SCRIPT_DIR/app.py" << 'EOF'

# Frontend serving routes
import os
from flask import send_from_directory

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')
EOF
    fi

    # Fix permissions
    sudo chown -R www-data:www-data "$FRONTEND_STATIC"
    sudo chmod -R 755 "$FRONTEND_STATIC"

    # Restart services
    sudo systemctl start gbot
    sudo systemctl start nginx

    # Clear Nginx cache
    sudo rm -rf /var/cache/nginx/*

    # Verify deployment
    verify_frontend_deployment

    echo -e "\n✅ Frontend fixes applied!"
    echo -e "🔄 Please clear your browser cache and try accessing the application again."
    echo -e "🌐 URL: ${BLUE}http://$(hostname -I | awk '{print $1}')${NC}"

    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Run main function
main "$@"
