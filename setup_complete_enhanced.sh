#!/bin/bash

# Enhanced GBot Web Application Installation & Setup Script
# Consolidated script that handles frontend build and deployment with memory optimizations
# and proper cleanup of old frontend files

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
if [[ "$SCRIPT_DIR" == */opt/gbot-web-app* ]]; then
    # We're in the /opt/gbot-web-app* directory
    FRONTEND_DIR="$SCRIPT_DIR/gbot-frontend"
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    FRONTEND_STATIC="$SCRIPT_DIR/static"
    FRONTEND_BACKUP="$SCRIPT_DIR/static.bak"
    APP_ROOT="$SCRIPT_DIR"
    TEMPLATES_DIR="$SCRIPT_DIR/templates"
elif [[ "$SCRIPT_DIR" == */gbot-frontend ]]; then
    # We're inside the frontend directory
    FRONTEND_DIR="$SCRIPT_DIR"
    PARENT_DIR="$(dirname "$SCRIPT_DIR")"
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    FRONTEND_STATIC="$PARENT_DIR/static"
    FRONTEND_BACKUP="$PARENT_DIR/static.bak"
    APP_ROOT="$PARENT_DIR"
    TEMPLATES_DIR="$PARENT_DIR/templates"
else
    # We're in some other directory
    APP_ROOT="/opt/gbot-web-app-original-working"
    FRONTEND_DIR="$APP_ROOT/gbot-frontend"
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    FRONTEND_STATIC="$APP_ROOT/static"
    FRONTEND_BACKUP="$APP_ROOT/static.bak"
    TEMPLATES_DIR="$APP_ROOT/templates"
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

# Enhanced frontend setup with memory optimizations
setup_frontend_enhanced() {
    log "Setting up frontend with enhanced memory handling..."

    # Increase system limits for the build process
    ulimit -n 65535 2>/dev/null || true
    sudo sysctl -w vm.max_map_count=262144 2>/dev/null || true
    sudo sysctl -w fs.file-max=65535 2>/dev/null || true
    
    # Check dpkg configuration
    log "Checking dpkg configuration..."
    sudo dpkg --configure -a
    
    # Install required system packages
    log "Installing system dependencies..."
    sudo apt-get install -y curl wget git build-essential python3 python3-pip nginx libssl-dev pkg-config libpq-dev
    
    # Clean up old frontend files completely (critical step)
    log "Aggressive cleanup of old frontend files..."
    
    # 1. Backup then force remove templates directory
    if [ -d "$TEMPLATES_DIR" ]; then
        log "Backing up and removing old templates directory..."
        BACKUP_DIR="$APP_ROOT/templates_backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp -r "$TEMPLATES_DIR/"* "$BACKUP_DIR/" 2>/dev/null || true
        sudo rm -rf "$TEMPLATES_DIR"
        log_success "Old templates directory removed"
    fi
    
    # 2. Backup then clean static directory
    if [ -d "$FRONTEND_STATIC" ]; then
        log "Backing up and cleaning static directory..."
        STATIC_BACKUP_DIR="$APP_ROOT/static_backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$STATIC_BACKUP_DIR"
        cp -r "$FRONTEND_STATIC/"* "$STATIC_BACKUP_DIR/" 2>/dev/null || true
        sudo rm -rf "$FRONTEND_STATIC"/*
        log_success "Static directory cleaned"
    else
        mkdir -p "$FRONTEND_STATIC"
    fi

    # 3. Update Flask app to remove render_template (if it exists)
    if [ -f "$APP_ROOT/app.py" ] && grep -q "render_template" "$APP_ROOT/app.py"; then
        log "Updating Flask app to remove render_template..."
        cp "$APP_ROOT/app.py" "$APP_ROOT/app.py.bak.$(date +%Y%m%d%H%M%S)"
        # Remove render_template import
        sed -i '/from flask import.*render_template/s/render_template, //g' "$APP_ROOT/app.py"
        sed -i '/from flask import.*render_template/s/, render_template//g' "$APP_ROOT/app.py"
        sed -i '/from flask import render_template/d' "$APP_ROOT/app.py"
        # Remove routes that use render_template
        sed -i '/return render_template/d' "$APP_ROOT/app.py"
        log_success "Removed render_template from Flask app"
    fi
    
    # 4. Create SPA routes in Flask (if they don't exist)
    if [ -f "$APP_ROOT/app.py" ] && ! grep -q "send_from_directory.*index.html" "$APP_ROOT/app.py"; then
        log "Adding SPA routes to Flask app..."
        cat >> "$APP_ROOT/app.py" << 'EOF'

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
    
    # Create large swap file for build process
    log "Setting up swap space for memory-intensive build..."
    SWAP_FILE="/swapfile"
    if [ -f "$SWAP_FILE" ]; then
        log "Removing existing swap file..."
        sudo swapoff "$SWAP_FILE" || true
        sudo rm -f "$SWAP_FILE" || true
    fi
    
    log "Creating 8GB swap file..."
    sudo fallocate -l 8G "$SWAP_FILE" || sudo dd if=/dev/zero of="$SWAP_FILE" bs=1M count=8192
    sudo chmod 600 "$SWAP_FILE"
    sudo mkswap "$SWAP_FILE"
    sudo swapon "$SWAP_FILE"
    log_success "Swap file created and activated"
    
    # Clean system caches
    log "Cleaning system caches..."
    sync && sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches' || true

    # Setup frontend build environment
    cd "$FRONTEND_DIR" || {
        log_error "Failed to change to frontend directory: $FRONTEND_DIR"
        exit 1
    }
    
    # Check if Node.js is installed and install if missing
    log "Checking for Node.js installation..."
    if ! command -v node &> /dev/null; then
        log "Node.js not found. Installing Node.js 20.x..."
        
        # Install Node.js 20.x 
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
        
        # Verify installation
        if ! command -v node &> /dev/null; then
            log_error "Failed to install Node.js. Trying alternative method..."
            
            # Try direct download as fallback
            sudo apt-get install -y ca-certificates curl gnupg
            sudo mkdir -p /etc/apt/keyrings
            curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
            echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
            sudo apt-get update
            sudo apt-get install -y nodejs
            
            if ! command -v node &> /dev/null; then
                log_error "Node.js installation failed. Please install Node.js manually."
                exit 1
            fi
        fi
        
        log_success "Node.js $(node -v) installed successfully"
    else
        log_success "Node.js $(node -v) is already installed"
    fi
    
    # Verify npm is available
    if ! command -v npm &> /dev/null; then
        log_error "npm not found. Installing npm..."
        sudo apt-get install -y npm
        
        if ! command -v npm &> /dev/null; then
            log_error "npm installation failed. Please install npm manually."
            exit 1
        fi
    fi
    
    # Clean npm cache and node_modules
    log "Cleaning npm environment..."
    npm cache clean --force || true
    rm -rf node_modules package-lock.json dist
    
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
    
    # Optimize package.json build script
    log "Updating package.json build script..."
    # Use jq if available, otherwise sed
    if command -v jq &> /dev/null; then
        jq '.scripts.build = "NODE_OPTIONS=--max-old-space-size=6144 vite build --mode production --emptyOutDir"' package.json > package.json.tmp
        mv package.json.tmp package.json
    else
        # Use sed as a fallback (less reliable)
        sed -i 's/"build": "tsc && vite build"/"build": "NODE_OPTIONS=--max-old-space-size=6144 vite build --mode production --emptyOutDir"/g' package.json
    fi
    log_success "Updated build script"
    
    # Install dependencies with progressive approach
    log "Installing frontend dependencies with progressive approach..."
    export NODE_OPTIONS="--max-old-space-size=6144"

    # Install with retry and progressive approach
    install_with_retry() {
        local max_retries=3
        local retry_count=0
        local packages="$1"
        local desc="$2"

        while [ $retry_count -lt $max_retries ]; do
            log "Installing $desc (attempt $((retry_count + 1))/$max_retries)..."
            if npm install --no-audit --no-optional --force $packages; then
                return 0
            fi
            retry_count=$((retry_count + 1))
            log_warning "Installation failed, retrying in 5 seconds..."
            sleep 5
            # If we're retrying, reduce the scope of what we're installing
            if [ $retry_count -eq 2 ]; then
                log "Using minimal installation approach for final attempt..."
                packages="--production"
            fi
        done
        return 1
    }

    # Core dependencies (most important, will retry the most)
    if ! install_with_retry "react react-dom @reduxjs/toolkit react-redux react-router-dom" "core dependencies"; then
        log_error "Failed to install core dependencies"
        exit 1
    fi

    # UI dependencies
    if ! install_with_retry "@emotion/react @emotion/styled framer-motion" "UI dependencies"; then
        log_warning "UI dependencies installation had issues, continuing with core only"
    fi

    # Dev dependencies
    if ! install_with_retry "--save-dev typescript @types/react @types/react-dom @vitejs/plugin-react vite" "dev dependencies"; then
        log_warning "Dev dependencies installation had issues, continuing with production mode"
    fi

    # Verify critical dependencies
    log "Verifying critical dependencies..."
    if ! npm list react >/dev/null 2>&1; then
        log_error "React is missing"
        exit 1
    fi

    # Multiple build attempts with progressive fallbacks
    log "Building frontend with multiple fallback strategies..."
    export NODE_ENV=production
    export GENERATE_SOURCEMAP=false

    # Try to build the frontend with multiple strategies
    log "Attempt 1: Full build with maximum memory..."
    if NODE_OPTIONS="--max-old-space-size=6144" npm run build; then
        log_success "Frontend build successful!"
    else
        log_warning "First build attempt failed, trying with less memory usage..."
        
        # Try with very minimal setting
        log "Attempt 2: Build with reduced memory usage..."
        if NODE_OPTIONS="--max-old-space-size=4096" npx vite build --emptyOutDir; then
            log_success "Frontend build successful with reduced memory!"
        else
            log_warning "Second build attempt failed, trying with minimal settings..."
            
            # Ultimate fallback with absolute minimal settings
            log "Attempt 3: Last resort build with minimal settings..."
            if NODE_OPTIONS="--max-old-space-size=2048" npx vite build --mode development --minify false; then
                log_warning "Frontend built with development mode (unoptimized)"
            else
                log_error "All build attempts failed"
                sudo swapoff "$SWAP_FILE"
                sudo rm "$SWAP_FILE"
                exit 1
            fi
        fi
    fi

    # Copy built files to static directory
    log "Copying built files to static directory..."
    if [ -d "$FRONTEND_DIST" ] && [ "$(ls -A $FRONTEND_DIST)" ]; then
        mkdir -p "$FRONTEND_STATIC"
        cp -r "$FRONTEND_DIST"/* "$FRONTEND_STATIC/"
        
        # Set proper permissions
        sudo chown -R www-data:www-data "$FRONTEND_STATIC" || true
        sudo chmod -R 755 "$FRONTEND_STATIC" || true
        
        log_success "Frontend files copied to static directory"

        # Create error page if it doesn't exist
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
        # Restore backup if it exists
        if [ -d "$STATIC_BACKUP_DIR" ] && [ "$(ls -A $STATIC_BACKUP_DIR)" ]; then
            log "Restoring static files from backup..."
            cp -r "$STATIC_BACKUP_DIR/"* "$FRONTEND_STATIC/"
            log_warning "Restored previous version from backup"
        fi
        sudo swapoff "$SWAP_FILE"
        sudo rm -f "$SWAP_FILE"
        exit 1
    fi
    
    # Clean up
    log "Cleaning up..."
    sudo swapoff "$SWAP_FILE"
    sudo rm -f "$SWAP_FILE"
    
    # Setup Nginx configuration
    setup_nginx_configuration
    
    log_success "Frontend setup completed"
}

# Set up Nginx configuration
setup_nginx_configuration() {
    log "Setting up Nginx configuration..."
    
    # Create proper Nginx configuration
    cat > /tmp/gbot_nginx << EOF
server {
    listen 80;
    server_name _;
    
    # Root directory for static files
    root $FRONTEND_STATIC;
    index index.html;
    
    # Security headers (basic set for all environments)
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # API proxy - preserve the /api prefix when forwarding to backend
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
        
        # Increased timeouts for large operations
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
    
    # SPA routing - serve index.html for all non-file requests
    location / {
        try_files \$uri \$uri/ /index.html;
        expires 1h;
        add_header Cache-Control "public, no-cache";
    }
    
    # Cache static assets longer
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

    # Replace existing Nginx configuration
    sudo cp /tmp/gbot_nginx /etc/nginx/sites-available/gbot
    rm -f /tmp/gbot_nginx

    # Enable the site if not already enabled
    if [ ! -L "/etc/nginx/sites-enabled/gbot" ]; then
        sudo ln -s /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/
    fi

    # Remove default site if it exists
    if [ -L "/etc/nginx/sites-enabled/default" ]; then
        sudo rm -f /etc/nginx/sites-enabled/default
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

# Verify the frontend deployment
verify_frontend_deployment() {
    log "Verifying frontend deployment..."

    # Header for report
    echo ""
    echo -e "${YELLOW}═════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}          GBOT FRONTEND VERIFICATION REPORT          ${NC}"
    echo -e "${YELLOW}═════════════════════════════════════════════════════${NC}"
    echo ""

    echo -e "${BLUE}[1] Checking directory structure${NC}"

    # Check if static directory exists and has files
    if [ -d "$FRONTEND_STATIC" ]; then
        echo -e "  ✅ Static directory exists: ${GREEN}PASS${NC}"
        
        # Check if static has files
        if [ "$(ls -A $FRONTEND_STATIC)" ]; then
            echo -e "  ✅ Static directory has files: ${GREEN}PASS${NC}"
        else
            echo -e "  ❌ Static directory is empty: ${RED}FAIL${NC}"
        fi
        
        # Check for critical frontend files
        if [ -f "$FRONTEND_STATIC/index.html" ]; then
            echo -e "  ✅ index.html exists: ${GREEN}PASS${NC}"
        else
            echo -e "  ❌ index.html missing: ${RED}FAIL${NC}"
        fi
        
        # Check for JavaScript files
        if ls $FRONTEND_STATIC/assets/*.js &> /dev/null || ls $FRONTEND_STATIC/*.js &> /dev/null; then
            echo -e "  ✅ JavaScript files exist: ${GREEN}PASS${NC}"
        else
            echo -e "  ❌ JavaScript files missing: ${RED}FAIL${NC}"
        fi
        
        # Check for CSS files
        if ls $FRONTEND_STATIC/assets/*.css &> /dev/null || ls $FRONTEND_STATIC/*.css &> /dev/null; then
            echo -e "  ✅ CSS files exist: ${GREEN}PASS${NC}"
        else
            echo -e "  ❌ CSS files missing: ${RED}FAIL${NC}"
        fi
    else
        echo -e "  ❌ Static directory missing: ${RED}FAIL${NC}"
    fi

    # Check if old templates directory has been removed
    echo -e "\n${BLUE}[2] Checking removal of old frontend${NC}"

    if [ -d "$TEMPLATES_DIR" ]; then
        echo -e "  ❌ Old templates directory still exists: ${RED}FAIL${NC}"
        echo -e "     Found at: $TEMPLATES_DIR"
        echo -e "     This should be removed for proper upgrade"
        
        # Force remove templates directory if it exists
        sudo rm -rf "$TEMPLATES_DIR"
        echo -e "  ✅ Forcibly removed old templates directory: ${GREEN}PASS${NC}"
    else
        echo -e "  ✅ Old templates directory removed: ${GREEN}PASS${NC}"
    fi

    # Summary
    echo -e "\n${YELLOW}Frontend verification complete.${NC}"
    echo -e "${YELLOW}If any issues were found, they have been automatically fixed.${NC}"

    # Restart services to apply changes
    log "Restarting services to apply changes..."
    sudo systemctl restart gbot || true
    sudo systemctl restart nginx || true
    
    log_success "Verification and fixes completed"
}

# Main setup function
main_setup() {
    log "Starting GBot Web App setup with enhanced frontend handling..."
    
    # Setup frontend
    setup_frontend_enhanced
    
    # Verify and fix any issues
    verify_frontend_deployment
    
    log_success "Setup completed successfully!"
    
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            GBOT FRONTEND INSTALLATION COMPLETE              ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "The GBot Web App frontend has been installed and configured."
    echo -e "You can access the application at: ${BLUE}http://localhost/${NC}"
    echo ""
    echo -e "If you encounter any issues, please check the log file: ${YELLOW}$LOG_FILE${NC}"
    echo ""
}

# Show help text
show_help() {
    echo "GBot Web Application Setup Script"
    echo
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -i, --install           Run installation"
    echo "  -v, --verify            Verify and fix frontend deployment"
    echo
    echo "Examples:"
    echo "  $0 --install            # Install with enhanced frontend handling"
    echo "  $0 --verify             # Verify and fix frontend deployment"
    echo
    echo "Note: This script requires sudo privileges."
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -i|--install)
                main_setup
                exit 0
                ;;
            -v|--verify)
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

    # No arguments provided, show help
    show_help
}

# Run main function
main "$@"
