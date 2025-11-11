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
FRONTEND_DIR="$SCRIPT_DIR/gbot-frontend"
FRONTEND_DIST="$FRONTEND_DIR/dist"
FRONTEND_STATIC="$SCRIPT_DIR/static"
FRONTEND_BACKUP="$SCRIPT_DIR/static.bak"

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

    # Install Node.js and npm if not present
    if ! command -v node &> /dev/null; then
        log "Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
        sudo apt-get install -y nodejs
    fi

    # Verify Node.js installation
    if ! command -v node &> /dev/null; then
        log_error "Node.js installation failed"
        exit 1
    fi

    # Backup existing static files
    if [ -d "$FRONTEND_STATIC" ]; then
        log "Backing up existing static files..."
        mv "$FRONTEND_STATIC" "$FRONTEND_BACKUP"
    fi

    # Create static directory
    mkdir -p "$FRONTEND_STATIC"

    # Build frontend
    log "Building frontend..."
    cd "$FRONTEND_DIR"
    
    # Install dependencies
    log "Installing frontend dependencies..."
    npm install

    # Build the application
    npm run build

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
    cp -r "$FRONTEND_DIST"/* "$FRONTEND_STATIC/"

    # Set proper permissions
    sudo chown -R www-data:www-data "$FRONTEND_STATIC"
    sudo chmod -R 755 "$FRONTEND_STATIC"

    # Clean up backup if everything succeeded
    if [ -d "$FRONTEND_BACKUP" ]; then
        rm -rf "$FRONTEND_BACKUP"
    fi

    log_success "Frontend setup completed"
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
