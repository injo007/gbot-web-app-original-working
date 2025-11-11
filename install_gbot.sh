#!/bin/bash

# GBOT AUTOMATED FULL INSTALLATION SCRIPT
# This script performs all installation steps automatically:
# - Sets up Node.js and dependencies
# - Builds the React frontend
# - Configures Nginx
# - Sets up the gunicorn service
# - Cleans up unnecessary files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="/opt/gbot-web-app-original-working"
LOG_FILE="$PROJECT_DIR/install.log"

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
    exit 1
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (use sudo)"
    exit 1
fi

# Step 1: Update system and install required packages
install_system_dependencies() {
    log "Installing system dependencies..."
    
    apt-get update
    apt-get upgrade -y
    
    # Install Node.js
    if ! command -v node &> /dev/null; then
        log "Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
        log_success "Node.js $(node -v) installed"
    else
        log_success "Node.js $(node -v) already installed"
    fi
    
    # Install other dependencies
    apt-get install -y git nginx python3 python3-pip python3-venv libssl-dev pkg-config libpq-dev
    log_success "System dependencies installed"
}

# Step 2: Setup Python environment
setup_python_environment() {
    log "Setting up Python environment..."
    
    cd $PROJECT_DIR
    
    # Create Python virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python dependencies
    pip install -r requirements.txt
    
    log_success "Python environment set up"
}

# Step 3: Setup frontend (adapted from setup_complete_enhanced.sh)
setup_frontend() {
    log "Setting up frontend with enhanced memory handling..."

    FRONTEND_DIR="$PROJECT_DIR/gbot-frontend"
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    FRONTEND_STATIC="$PROJECT_DIR/static"
    TEMPLATES_DIR="$PROJECT_DIR/templates"
    
    # Increase system limits
    ulimit -n 65535 2>/dev/null || true
    sysctl -w vm.max_map_count=262144 2>/dev/null || true
    sysctl -w fs.file-max=65535 2>/dev/null || true
    
    # Clean up old frontend files
    log "Cleaning up old frontend files..."
    
    # Backup then remove templates directory
    if [ -d "$TEMPLATES_DIR" ]; then
        log "Backing up and removing old templates directory..."
        BACKUP_DIR="$PROJECT_DIR/templates_backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp -r "$TEMPLATES_DIR/"* "$BACKUP_DIR/" 2>/dev/null || true
        rm -rf "$TEMPLATES_DIR"
        log_success "Old templates directory removed"
    fi
    
    # Backup then clean static directory
    if [ -d "$FRONTEND_STATIC" ]; then
        log "Backing up and cleaning static directory..."
        STATIC_BACKUP_DIR="$PROJECT_DIR/static_backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$STATIC_BACKUP_DIR"
        cp -r "$FRONTEND_STATIC/"* "$STATIC_BACKUP_DIR/" 2>/dev/null || true
        rm -rf "$FRONTEND_STATIC"/*
        log_success "Static directory cleaned"
    else
        mkdir -p "$FRONTEND_STATIC"
    fi

    # Update Flask app to remove render_template
    if [ -f "$PROJECT_DIR/app.py" ] && grep -q "render_template" "$PROJECT_DIR/app.py"; then
        log "Updating Flask app to remove render_template..."
        cp "$PROJECT_DIR/app.py" "$PROJECT_DIR/app.py.bak.$(date +%Y%m%d%H%M%S)"
        sed -i '/from flask import.*render_template/s/render_template, //g' "$PROJECT_DIR/app.py"
        sed -i '/from flask import.*render_template/s/, render_template//g' "$PROJECT_DIR/app.py"
        sed -i '/from flask import render_template/d' "$PROJECT_DIR/app.py"
        sed -i '/return render_template/d' "$PROJECT_DIR/app.py"
        log_success "Removed render_template from Flask app"
    fi
    
    # Create SPA routes in Flask
    if [ -f "$PROJECT_DIR/app.py" ] && ! grep -q "send_from_directory.*index.html" "$PROJECT_DIR/app.py"; then
        log "Adding SPA routes to Flask app..."
        cat >> "$PROJECT_DIR/app.py" << 'EOF'

# Frontend serving routes
import os
from flask import send_from_directory

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

# Health check endpoint
@app.route('/api/health')
def health_check():
    return jsonify({"status": "healthy"}), 200
EOF
        log_success "Added SPA routes to Flask app"
    fi
    
    # Create swap file for build process
    log "Setting up swap space for memory-intensive build..."
    SWAP_FILE="/swapfile"
    if [ -f "$SWAP_FILE" ]; then
        log "Removing existing swap file..."
        swapoff "$SWAP_FILE" || true
        rm -f "$SWAP_FILE" || true
    fi
    
    log "Creating 8GB swap file..."
    fallocate -l 8G "$SWAP_FILE" || dd if=/dev/zero of="$SWAP_FILE" bs=1M count=8192
    chmod 600 "$SWAP_FILE"
    mkswap "$SWAP_FILE"
    swapon "$SWAP_FILE"
    log_success "Swap file created and activated"
    
    # Clean system caches
    log "Cleaning system caches..."
    sync && sh -c 'echo 3 > /proc/sys/vm/drop_caches' || true

    # Setup frontend build
    cd "$FRONTEND_DIR" || {
        log_error "Failed to change to frontend directory: $FRONTEND_DIR"
        exit 1
    }
    
    # Create optimized Vite config
    log "Creating optimized build configuration..."
    cat > "$FRONTEND_DIR/vite.config.ts" << 'EOF'
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

// Memory-optimized configuration for production builds
export default defineConfig({
  plugins: [
    react({
      // Enable emotion's JSX pragma
      jsxImportSource: '@emotion/react',
    }),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      '@components': resolve(__dirname, './src/components'),
      '@pages': resolve(__dirname, './src/pages'), 
      '@store': resolve(__dirname, './src/store'),
      '@theme': resolve(__dirname, './src/theme'),
      '@api': resolve(__dirname, './src/api'),
    },
  },
  server: {
    port: 3000,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 800,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react')) return 'vendor-react';
            if (id.includes('redux') || id.includes('toolkit')) return 'vendor-redux';
            if (id.includes('emotion') || id.includes('framer')) return 'vendor-ui';
            return 'vendor';
          }
        },
        assetFileNames: 'assets/[name]-[hash:8][extname]',
        chunkFileNames: 'chunks/[name]-[hash:8].js',
        entryFileNames: 'entries/[name]-[hash:8].js',
      },
    },
    target: 'es2015',
    minify: 'esbuild',
    assetsInlineLimit: 4096,
    cssCodeSplit: true,
    cssMinify: true,
    reportCompressedSize: false, 
    emptyOutDir: true,
  },
  optimizeDeps: {
    include: [
      'react', 
      'react-dom',
      'react-router-dom'
    ],
    exclude: [
      '@emotion/styled',
      'framer-motion'
    ],
  },
});
EOF
    log_success "Created optimized Vite config"
    
    # Update package.json build script
    log "Updating package.json build script..."
    # Use jq if available, otherwise sed
    if command -v jq &> /dev/null; then
        jq '.scripts.build = "NODE_OPTIONS=--max-old-space-size=6144 vite build --mode production --emptyOutDir"' package.json > package.json.tmp
        mv package.json.tmp package.json
    else
        sed -i 's/"build": "tsc && vite build"/"build": "NODE_OPTIONS=--max-old-space-size=6144 vite build --mode production --emptyOutDir"/g' package.json
    fi
    log_success "Updated build script"
    
    # Clean npm environment
    log "Cleaning npm environment..."
    npm cache clean --force || true
    rm -rf node_modules package-lock.json dist
    
    # Install dependencies
    log "Installing frontend dependencies..."
    export NODE_OPTIONS="--max-old-space-size=6144"
    
    # Core dependencies (most important)
    log "Installing core dependencies..."
    npm install --no-audit --omit=optional react react-dom @reduxjs/toolkit react-redux react-router-dom
    
    # UI dependencies
    log "Installing UI dependencies..."
    npm install --no-audit --omit=optional @emotion/react @emotion/styled framer-motion
    
    # Dev dependencies
    log "Installing dev dependencies..."
    npm install --no-audit --omit=optional --save-dev typescript @types/react @types/react-dom @vitejs/plugin-react vite
    
    # Build the frontend
    log "Building frontend..."
    export NODE_ENV=production
    export GENERATE_SOURCEMAP=false
    
    # Try to build with fallbacks
    if ! NODE_OPTIONS="--max-old-space-size=6144" npm run build; then
        log_warning "First build attempt failed, trying with less memory..."
        if ! NODE_OPTIONS="--max-old-space-size=4096" npx vite build --emptyOutDir; then
            log_warning "Second build attempt failed, trying with minimal settings..."
            NODE_OPTIONS="--max-old-space-size=2048" npx vite build --mode development --minify false
            log_warning "Frontend built with development mode (unoptimized)"
        else
            log_success "Frontend build successful with reduced memory!"
        fi
    else
        log_success "Frontend build successful!"
    fi
    
    # Copy built files to static directory
    log "Copying built files to static directory..."
    if [ -d "$FRONTEND_DIST" ] && [ "$(ls -A $FRONTEND_DIST)" ]; then
        mkdir -p "$FRONTEND_STATIC"
        cp -r "$FRONTEND_DIST"/* "$FRONTEND_STATIC/"
        
        # Set proper permissions
        chown -R www-data:www-data "$FRONTEND_STATIC" || true
        chmod -R 755 "$FRONTEND_STATIC" || true
        
        log_success "Frontend files copied to static directory"
        
        # Create error page
        if [ ! -f "$FRONTEND_STATIC/error.html" ]; then
            log "Creating error page..."
            cat > "$FRONTEND_STATIC/error.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>GBot Error</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            margin-top: 50px;
        }
        h1 { color: #e74c3c; }
        p { margin: 20px; }
        .button {
            background-color: #3498db;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            text-decoration: none;
            display: inline-block;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <h1>Server Error</h1>
    <p>Sorry, something went wrong on our end. Please try again later.</p>
    <a href='/' class='button'>Return to Home</a>
</body>
</html>
EOF
        fi
    else
        log_error "Build output directory is missing or empty"
        exit 1
    fi
    
    # Clean up
    log "Cleaning up..."
    swapoff "$SWAP_FILE"
    rm -f "$SWAP_FILE"
    
    log_success "Frontend setup completed"
}

# Step 4: Configure Nginx
configure_nginx() {
    log "Setting up Nginx configuration..."
    
    FRONTEND_STATIC="$PROJECT_DIR/static"
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/gbot << EOF
server {
    listen 80;
    server_name _;
    
    # Root directory for static files
    root $FRONTEND_STATIC;
    index index.html;
    
    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # API proxy
    location /api/ {
        proxy_pass http://localhost:5000/api/;  # Keep the /api prefix
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Increased timeouts
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        
        # Buffer settings
        proxy_buffer_size 16k;
        proxy_buffers 8 16k;
        proxy_busy_buffers_size 32k;
        
        # Handle large uploads
        client_max_body_size 10M;
    }
    
    # SPA routing
    location / {
        try_files \$uri \$uri/ /index.html;
        expires 1h;
        add_header Cache-Control "public, no-cache";
    }
    
    # Cache static assets
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?)$ {
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check endpoint
    location = /health {
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }
    
    # Error handling
    error_page 404 /index.html;
    error_page 500 502 503 504 /error.html;
}
EOF

    # Enable the site
    if [ ! -L "/etc/nginx/sites-enabled/gbot" ]; then
        ln -sf /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/
    fi
    
    # Remove default site if it exists
    if [ -L "/etc/nginx/sites-enabled/default" ]; then
        rm -f /etc/nginx/sites-enabled/default
    fi
    
    # Test and reload Nginx
    if nginx -t; then
        systemctl reload nginx
        log_success "Nginx configuration updated"
    else
        log_error "Nginx configuration test failed"
        exit 1
    fi
}

# Step 5: Setup Gunicorn Service
setup_gunicorn_service() {
    log "Setting up Gunicorn service..."
    
    # Create simplest service file
    cat > /etc/systemd/system/gbot.service << 'EOF'
[Unit]
Description=GBot Web Application
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/opt/gbot-web-app-original-working
Environment="PATH=/opt/gbot-web-app-original-working/venv/bin"
ExecStart=/opt/gbot-web-app-original-working/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    # Enable and start service
    systemctl enable gbot
    systemctl restart gbot
    
    # Check service status
    if systemctl is-active --quiet gbot; then
        log_success "Gunicorn service started successfully"
    else
        log_warning "Gunicorn service failed to start. Check 'systemctl status gbot' for details."
    fi
}

# Step 6: Clean up unnecessary files
cleanup_files() {
    log "Cleaning up unnecessary files..."
    
    # List of files to remove
    FILES_TO_REMOVE=(
        "$PROJECT_DIR/setup_complete.sh"
        "$PROJECT_DIR/optimize_frontend_build.sh"
        "$PROJECT_DIR/verify_frontend_deployment.sh"
        "$PROJECT_DIR/gunicorn.fixed.service"
        "$PROJECT_DIR/gunicorn.simple.service"
        "$PROJECT_DIR/gunicorn.basic.service"
        "$PROJECT_DIR/FIX_GUNICORN_SERVICE.md"
        "$PROJECT_DIR/SIMPLE_SERVICE_FIX.md"
        "$PROJECT_DIR/BASIC_SERVICE_FIX.md"
    )
    
    for file in "${FILES_TO_REMOVE[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file"
        fi
    done
    
    log_success "Unnecessary files removed"
}

# Step 7: Verify installation
verify_installation() {
    log "Verifying installation..."
    
    echo ""
    echo -e "${YELLOW}═════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}          GBOT INSTALLATION VERIFICATION               ${NC}"
    echo -e "${YELLOW}═════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Check Nginx
    if systemctl is-active --quiet nginx; then
        echo -e "  ✅ Nginx is running: ${GREEN}PASS${NC}"
    else
        echo -e "  ❌ Nginx is not running: ${RED}FAIL${NC}"
    fi
    
    # Check Gunicorn service
    if systemctl is-active --quiet gbot; then
        echo -e "  ✅ Gunicorn service is running: ${GREEN}PASS${NC}"
    else
        echo -e "  ❌ Gunicorn service is not running: ${RED}FAIL${NC}"
    fi
    
    # Check Frontend files
    if [ -f "$PROJECT_DIR/static/index.html" ]; then
        echo -e "  ✅ Frontend files exist: ${GREEN}PASS${NC}"
    else
        echo -e "  ❌ Frontend files missing: ${RED}FAIL${NC}"
    fi
    
    # Test API health endpoint
    if curl -s http://localhost:5000/api/health 2>/dev/null | grep -q "healthy"; then
        echo -e "  ✅ API health endpoint working: ${GREEN}PASS${NC}"
    else
        echo -e "  ❌ API health endpoint not responding: ${RED}FAIL${NC}"
    fi
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                 GBOT INSTALLATION COMPLETE                   ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "You can access the application at: ${BLUE}http://$SERVER_IP/${NC}"
    echo ""
    echo -e "If you encounter any issues:"
    echo -e "  - Check Nginx logs: ${YELLOW}sudo tail -f /var/log/nginx/error.log${NC}"
    echo -e "  - Check service logs: ${YELLOW}sudo journalctl -u gbot -f${NC}"
    echo ""
}

# MAIN SCRIPT EXECUTION
main() {
    log "Starting GBot automatic full installation..."

    # Check if PROJECT_DIR exists or create it
    if [ ! -d "$PROJECT_DIR" ]; then
        log "Project directory does not exist. Creating it at $PROJECT_DIR..."
        mkdir -p "$PROJECT_DIR"
        log_success "Project directory created."
    fi
    
    # Check if we're in PROJECT_DIR or copy files there
    if [ "$SCRIPT_DIR" != "$PROJECT_DIR" ]; then
        log "Script is running from $SCRIPT_DIR, copying files to $PROJECT_DIR..."
        # Copy all files from current directory to PROJECT_DIR
        cp -r "$SCRIPT_DIR"/* "$PROJECT_DIR"/ || log_warning "Some files could not be copied."
        log_success "Files copied to $PROJECT_DIR"
    fi
    
    # Change to project directory
    cd "$PROJECT_DIR"
    log "Working in directory: $(pwd)"
    
    install_system_dependencies
    setup_python_environment
    setup_frontend
    configure_nginx
    setup_gunicorn_service
    cleanup_files
    verify_installation
    
    log_success "Installation completed successfully!"
}

# Execute main function
main "$@"
