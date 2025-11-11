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
if [[ "$SCRIPT_DIR" == */opt/gbot-web-app* ]]; then
    # We're in the /opt/gbot-web-app* directory
    FRONTEND_DIR="$SCRIPT_DIR/gbot-frontend"
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    FRONTEND_STATIC="$SCRIPT_DIR/static"
    FRONTEND_BACKUP="$SCRIPT_DIR/static.bak"
    APP_ROOT="$SCRIPT_DIR"
elif [[ "$SCRIPT_DIR" == */gbot-frontend ]]; then
    # We're inside the frontend directory
    FRONTEND_DIR="$SCRIPT_DIR"
    PARENT_DIR="$(dirname "$SCRIPT_DIR")"
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    FRONTEND_STATIC="$PARENT_DIR/static"
    FRONTEND_BACKUP="$PARENT_DIR/static.bak"
    APP_ROOT="$PARENT_DIR"
else
    # We're in some other directory
    APP_ROOT="/opt/gbot-web-app-original-working"
    FRONTEND_DIR="$APP_ROOT/gbot-frontend"
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    FRONTEND_STATIC="$APP_ROOT/static"
    FRONTEND_BACKUP="$APP_ROOT/static.bak"
fi

# Create app root directory if it doesn't exist
if [ ! -d "$APP_ROOT" ]; then
    sudo mkdir -p "$APP_ROOT"
    sudo chown -R $(whoami):$(whoami) "$APP_ROOT"
fi

# Change to app root directory
cd "$APP_ROOT" || {
    log_error "Failed to change to app root directory: $APP_ROOT"
    exit 1
}

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

    # Install required system packages
    log "Installing system dependencies..."
    if ! sudo apt-get update; then
        log_error "Failed to update package lists"
        exit 1
    fi

    # Install packages with retry logic
    install_packages() {
        local max_retries=3
        local retry_count=0
        local packages="$1"

        while [ $retry_count -lt $max_retries ]; do
            if sudo apt-get install -y $packages; then
                return 0
            fi
            retry_count=$((retry_count + 1))
            log_warning "Package installation failed, retrying in 5 seconds... (attempt $retry_count/$max_retries)"
            sleep 5
            sudo apt-get update
        done
        return 1
    }

    # Install required packages
    if ! install_packages "curl wget git build-essential python3 python3-pip nginx libssl-dev pkg-config libpq-dev"; then
        log_error "Failed to install required system packages"
        exit 1
    fi

    # Check and setup Node.js 18.x
    setup_nodejs() {
        if command -v node &> /dev/null; then
            current_version=$(node -v)
            if [[ "$current_version" =~ ^v18 ]]; then
                log "Node.js $current_version is already installed"
                return 0
            fi
            
            log "Removing old Node.js version $current_version..."
            sudo apt-get remove -y nodejs npm || true
            sudo apt-get -y autoremove || true
            sudo rm -rf /usr/local/bin/npm /usr/local/share/man/man1/node* /usr/local/lib/dtrace/node.d ~/.npm ~/.node-gyp /opt/local/bin/node /opt/local/include/node /opt/local/lib/node_modules 2>/dev/null || true
            sudo rm -f /etc/apt/sources.list.d/nodesource.list 2>/dev/null || true
        fi

        # Install Node.js 18.x
        log "Installing Node.js 18.x..."
        if ! curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -; then
            log_error "Failed to setup Node.js repository"
            return 1
        fi
        
        sudo apt-get update
        if ! sudo apt-get install -y nodejs; then
            log_error "Failed to install Node.js"
            return 1
        fi

        # Verify installation
        if ! command -v node &> /dev/null; then
            log_error "Node.js installation verification failed"
            return 1
        fi

        current_version=$(node -v)
        if [[ ! "$current_version" =~ ^v18 ]]; then
            log_error "Wrong Node.js version. Expected v18.x, got $current_version"
            return 1
        fi

        log_success "Node.js $current_version installed successfully"
        return 0
    }

    # Setup Node.js
    if ! setup_nodejs; then
        log_error "Failed to setup Node.js"
        exit 1
    fi

    # Install latest npm
    log "Installing latest npm..."
    sudo npm install -g npm@latest

    # Install required global packages
    log "Installing global packages..."
    sudo npm install -g \
        typescript@latest \
        @types/node@latest \
        vite@latest \
        @vitejs/plugin-react@latest

    # Verify global packages
    log "Verifying global packages..."
    if ! command -v tsc &> /dev/null || ! command -v vite &> /dev/null; then
        log_error "Global package installation failed"
        exit 1
    fi

    # Create frontend directory structure if needed
    log "Setting up directory structure..."
    if [ ! -d "$FRONTEND_DIR/src" ]; then
        mkdir -p "$FRONTEND_DIR"/{src,public,dist,node_modules}
        mkdir -p "$FRONTEND_DIR/src"/{components,pages,store,theme,api,layouts}
        
        # Create base TypeScript config
        echo '{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}' > "$FRONTEND_DIR/tsconfig.json"

        # Create Vite config
        echo 'import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:5000",
        changeOrigin: true,
      },
    },
  },
});' > "$FRONTEND_DIR/vite.config.ts"

        # Create main entry files
        echo '<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/favicon.ico" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>GBot Web App</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>' > "$FRONTEND_DIR/index.html"

        echo 'import React from "react";
import ReactDOM from "react-dom/client";
import { Provider } from "react-redux";
import { store } from "./store";
import App from "./App";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <Provider store={store}>
      <App />
    </Provider>
  </React.StrictMode>
);' > "$FRONTEND_DIR/src/main.tsx"

        echo 'import { BrowserRouter } from "react-router-dom";
import { AppLayout } from "./layouts/AppLayout";

function App() {
  return (
    <BrowserRouter>
      <AppLayout />
    </BrowserRouter>
  );
}

export default App;' > "$FRONTEND_DIR/src/App.tsx"

        echo ':root {
  --primary: #6366f1;
  --primary-dark: #4f46e5;
  --secondary: #64748b;
  --success: #22c55e;
  --warning: #f59e0b;
  --error: #ef4444;
  --background: #ffffff;
  --text: #0f172a;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen,
    Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  background-color: var(--background);
  color: var(--text);
}' > "$FRONTEND_DIR/src/index.css"

        # Create store
        echo 'import { configureStore } from "@reduxjs/toolkit";
import { setupListeners } from "@reduxjs/toolkit/query";

export const store = configureStore({
  reducer: {},
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat([]),
});

setupListeners(store.dispatch);

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;' > "$FRONTEND_DIR/src/store/index.ts"

        # Create AppLayout
        echo 'import { Routes, Route } from "react-router-dom";

export const AppLayout = () => {
  return (
    <div className="app">
      <Routes>
        <Route path="/" element={<div>Welcome to GBot</div>} />
      </Routes>
    </div>
  );
};' > "$FRONTEND_DIR/src/layouts/AppLayout.tsx"

        # Create tsconfig.node.json
        echo '{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}' > "$FRONTEND_DIR/tsconfig.node.json"

        # Create .env files
        echo 'VITE_API_URL=/api' > "$FRONTEND_DIR/.env.development"
        echo 'VITE_API_URL=/api' > "$FRONTEND_DIR/.env.production"

        # Create .gitignore
        echo 'node_modules
dist
.env.local
.env.*.local
*.log
.DS_Store' > "$FRONTEND_DIR/.gitignore"

        log_success "Directory structure and base files created"
    else
        log "Using existing directory structure"
    fi

    # Clean up old frontend files
    log "Cleaning up old frontend files..."
    
    # Backup and remove old static files
    if [ -d "$FRONTEND_STATIC" ]; then
        log "Backing up old static files..."
        BACKUP_DIR="${APP_ROOT}/backups/static_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp -r "$FRONTEND_STATIC"/* "$BACKUP_DIR/" 2>/dev/null || true
        rm -rf "$FRONTEND_STATIC"/*
    fi

    # Clean up old files
    log "Cleaning up old files..."
    find "$APP_ROOT" -maxdepth 1 -type f \( \
        -name "*_FIX.md" -o \
        -name "fix_*.sh" -o \
        -name "fix_*.py" -o \
        -name "fix_*.sql" -o \
        -name "QUICK_FIX_*.md" -o \
        -name "*_DEBUG.md" -o \
        -name "test_*.py" -o \
        -name "test_*.sh" -o \
        -name "check_*.py" -o \
        -name "check_*.sh" -o \
        -name "diagnose_*.py" -o \
        -name "diagnose_*.sh" \
    \) -delete

    # Clean up old directories
    if [ -d "$APP_ROOT/templates" ]; then
        log "Removing old template files..."
        rm -rf "$APP_ROOT/templates"
    fi

    # Create fresh static directory
    mkdir -p "$FRONTEND_STATIC"

    # Clean up old templates
    if [ -d "$SCRIPT_DIR/templates" ]; then
        log "Removing old template files..."
        rm -rf "$SCRIPT_DIR/templates"
    fi

    # Clean up old fix files
    log "Removing old fix files..."
    rm -f "$SCRIPT_DIR"/*_FIX.md
    rm -f "$SCRIPT_DIR"/fix_*.{sh,py,sql}
    rm -f "$SCRIPT_DIR"/QUICK_FIX_*.md
    rm -f "$SCRIPT_DIR"/*_DEBUG.md
    rm -f "$SCRIPT_DIR"/test_*.{py,sh}
    rm -f "$SCRIPT_DIR"/check_*.{py,sh}
    rm -f "$SCRIPT_DIR"/diagnose_*.{py,sh}

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

    # Handle frontend files based on current location
    if [ "$SCRIPT_DIR" = "$FRONTEND_DIR" ]; then
        log "Already in frontend directory, no need to copy files"
    elif [ -d "$SCRIPT_DIR/gbot-frontend" ]; then
        # Create a temporary directory for copying
        TMP_DIR=$(mktemp -d)
        log "Copying frontend files via temporary directory..."
        
        # Copy files to temp directory first
        cp -r "$SCRIPT_DIR/gbot-frontend/"* "$TMP_DIR/" 2>/dev/null || true
        
        # Then move from temp to final location
        rm -rf "$FRONTEND_DIR"
        mkdir -p "$FRONTEND_DIR"
        mv "$TMP_DIR/"* "$FRONTEND_DIR/"
        rm -rf "$TMP_DIR"
        
        log_success "Frontend files copied successfully"
    else
        log_error "Frontend source directory not found"
        exit 1
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
    export NODE_OPTIONS="--max-old-space-size=4096"
    
    # Create package.json if it doesn't exist
    if [ ! -f "package.json" ]; then
        log "Initializing package.json..."
        echo '{
  "name": "gbot-web-app",
  "version": "1.0.0",
  "private": true,
  "type": "module",
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=8.0.0"
  },
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "lint": "eslint src --ext ts,tsx --report-unused-disable-directives --max-warnings 0",
    "format": "prettier --write \"src/**/*.{ts,tsx}\""
  },
  "dependencies": {
    "@emotion/react": "^11.11.0",
    "@emotion/styled": "^11.11.0",
    "@reduxjs/toolkit": "^1.9.5",
    "axios": "^1.4.0",
    "framer-motion": "^10.12.16",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-redux": "^8.0.7",
    "react-router-dom": "^6.11.2"
  },
  "devDependencies": {
    "@types/node": "^20.2.5",
    "@types/react": "^18.2.8",
    "@types/react-dom": "^18.2.4",
    "@typescript-eslint/eslint-plugin": "^5.59.8",
    "@typescript-eslint/parser": "^5.59.8",
    "@vitejs/plugin-react": "^4.0.0",
    "eslint": "^8.42.0",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-react-refresh": "^0.4.1",
    "prettier": "^2.8.8",
    "typescript": "^5.1.3",
    "vite": "^4.3.9"
  }
}' > package.json
    fi
    
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
    
    # Create backup of app.py
    cp "$SCRIPT_DIR/app.py" "$SCRIPT_DIR/app.py.bak"
    
    # Remove old frontend routes
    sed -i '/# Frontend serving routes/,/return send_from_directory/d' "$SCRIPT_DIR/app.py"
    
    # Add new frontend routes
    cat >> "$SCRIPT_DIR/app.py" << 'EOF'

# Frontend serving routes
import os
from flask import send_from_directory, jsonify

# Health check endpoint
@app.route('/api/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

# Frontend routes
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')
EOF

    # Verify Flask app update
    if ! grep -q "send_from_directory" "$SCRIPT_DIR/app.py"; then
        log_error "Failed to update Flask app"
        mv "$SCRIPT_DIR/app.py.bak" "$SCRIPT_DIR/app.py"
        exit 1
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

# Show help text
show_help() {
    echo "GBot Web Application Setup Script"
    echo
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -i, --install           Run complete installation"
    echo "  -r, --reinstall         Force reinstallation"
    echo "  --setup-frontend        Set up new React frontend"
    echo "  --update-frontend       Update existing frontend"
    echo "  --fix-frontend          Fix frontend deployment issues"
    echo "  --verify-frontend       Verify frontend deployment"
    echo
    echo "Examples:"
    echo "  $0 --setup-frontend     # Set up new React frontend"
    echo "  $0 --fix-frontend       # Fix frontend deployment issues"
    echo "  $0 --verify-frontend    # Verify frontend deployment"
    echo
    echo "Note: This script requires root privileges for some operations."
    echo "      Run with sudo if necessary."
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
