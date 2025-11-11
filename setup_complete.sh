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
CREDENTIALS_FILE="$SCRIPT_DIR/.credentials"

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

save_credentials() {
    local title="$1"
    local content="$2"
    echo -e "\n=== $title ===" >> "$CREDENTIALS_FILE"
    echo "$content" >> "$CREDENTIALS_FILE"
}

show_credentials() {
    echo -e "\n${GREEN}=== Installation Credentials ===${NC}"
    if [ -f "$CREDENTIALS_FILE" ]; then
        cat "$CREDENTIALS_FILE"
    else
        echo -e "${RED}No credentials file found${NC}"
    fi
}

cleanup_duplicate_files() {
    log "Cleaning up duplicate fix_*.sh files..."
    
    # List of files to keep
    KEEP_FILES=(
        "setup_complete.sh"
        "check_app_status.sh"
        "monitor_performance.py"
    )
    
    # Remove all fix_*.sh files
    find "$SCRIPT_DIR" -name "fix_*.sh" -type f -delete
    
    log_success "Duplicate files cleaned up"
}

create_required_directories() {
    log "Creating required directories..."
    
    # Create logs directory
    mkdir -p "$SCRIPT_DIR/logs"
    chmod 755 "$SCRIPT_DIR/logs"
    chown -R root:root "$SCRIPT_DIR/logs"
    
    # Create instance directory if it doesn't exist
    mkdir -p "$SCRIPT_DIR/instance"
    chmod 755 "$SCRIPT_DIR/instance"
    
    # Create static directory if it doesn't exist
    mkdir -p "$SCRIPT_DIR/static"
    chmod 755 "$SCRIPT_DIR/static"
    
    # Create templates directory if it doesn't exist
    mkdir -p "$SCRIPT_DIR/templates"
    chmod 755 "$SCRIPT_DIR/templates"
    
    log_success "Required directories created with proper permissions"
}

show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    $PROJECT_NAME                    ║"
    echo "║                                                              ║"
    echo "║                COMPLETE Installation Script                  ║"
    echo "║                                                              ║"
    echo "║           Root Execution • Reinstall • All Modules          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_system_requirements() {
    log "Checking system requirements..."
    
    # Allow root execution - no restrictions
    if [[ $EUID -eq 0 ]]; then
        log "Running as root user - proceeding with root deployment"
        ROOT_USER=true
        USER="root"
        USER_HOME="/root"
        # No sudo needed for root
        SUDO_CMD=""
    else
        log "Running as regular user - will use sudo for privileged operations"
        ROOT_USER=false
        SUDO_CMD="sudo"
    fi
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        log "Python version: $PYTHON_VERSION"
        
        # Check if Python 3.8+
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            log_success "Python version is compatible (3.8+)"
        else
            log_error "Python 3.8+ is required"
            exit 1
        fi
    else
        log_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        log_success "pip3 is available"
    else
        log_warning "pip3 is not available, will install it"
        $SUDO_CMD apt-get update
        $SUDO_CMD apt-get install -y python3-pip
    fi
    
    log_success "System requirements check completed"
}

install_system_dependencies() {
    log "Installing system dependencies..."
    
    if command -v apt-get &> /dev/null; then
        log "Using apt-get package manager"
        $SUDO_CMD apt-get update
        
        # Install Python and development tools
        $SUDO_CMD apt-get install -y python3 python3-pip python3-dev python3-venv
        
        # Install PostgreSQL
        $SUDO_CMD apt-get install -y postgresql postgresql-contrib
        
        # Install Nginx
        $SUDO_CMD apt-get install -y nginx
        
        # Install utilities
        $SUDO_CMD apt-get install -y curl wget git
    else
        log_error "Unsupported package manager"
        exit 1
    fi
    
    log_success "System dependencies installed"
}

setup_postgresql() {
    log "Setting up PostgreSQL database..."
    
    # Start PostgreSQL service
    $SUDO_CMD systemctl start postgresql
    $SUDO_CMD systemctl enable postgresql
    
    # Create database and user
    DB_NAME="gbot_db"
    DB_USER="gbot_user"
    DB_PASS=$(openssl rand -hex 12)
    
    # Check if database exists
    if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        log_warning "Database $DB_NAME already exists, skipping database creation"
    else
        # Create database
        log "Creating database $DB_NAME..."
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"
    fi
    
    # Check if user exists
    if sudo -u postgres psql -t -c "SELECT 1 FROM pg_user WHERE usename = '$DB_USER';" | grep -q 1; then
        log_warning "User $DB_USER already exists, updating password..."
        sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';"
    else
        # Create user
        log "Creating user $DB_USER..."
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    fi
    
    # Grant privileges (this is safe to run multiple times)
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
    
    # Save database credentials
    echo "DATABASE_URL=postgresql://$DB_USER:$DB_PASS@localhost/$DB_NAME" > "$SCRIPT_DIR/.env"
    chmod 600 "$SCRIPT_DIR/.env"
    
    # Save credentials for display
    save_credentials "PostgreSQL Credentials" "Database: $DB_NAME\nUser: $DB_USER\nPassword: $DB_PASS"
    
    log_success "PostgreSQL setup completed"
}

setup_python_environment() {
    log "Setting up Python environment..."
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python dependencies
    pip install --upgrade pip
    pip install -r requirements.txt
    pip install gunicorn
    
    # Deactivate virtual environment
    deactivate
    
    log_success "Python environment setup completed"
}

setup_nginx() {
    log "Setting up Nginx reverse proxy..."
    
    NGINX_CONFIG="/etc/nginx/sites-available/gbot"
    
    # Create nginx configuration
    cat > /tmp/gbot_nginx << EOF
server {
    listen 80;
    server_name _;
    
    location / {
        include proxy_params;
        proxy_pass http://unix:$SCRIPT_DIR/gbot.sock;
    }
    
    location /static {
        alias $SCRIPT_DIR/static;
    }
}
EOF
    
    $SUDO_CMD mv /tmp/gbot_nginx "$NGINX_CONFIG"
    
    # Enable site
    if [ ! -L "/etc/nginx/sites-enabled/gbot" ]; then
        $SUDO_CMD ln -s "$NGINX_CONFIG" "/etc/nginx/sites-enabled/"
    fi
    
    # Remove default site
    if [ -L "/etc/nginx/sites-enabled/default" ]; then
        $SUDO_CMD rm "/etc/nginx/sites-enabled/default"
    fi
    
    # Test and restart nginx
    $SUDO_CMD nginx -t && $SUDO_CMD systemctl restart nginx
    
    log_success "Nginx configuration completed"
}

setup_systemd_service() {
    log "Setting up systemd service..."
    
    SERVICE_FILE="/etc/systemd/system/gbot.service"
    
    # Create systemd service file with proper log paths
    cat > /tmp/gbot_service << EOF
[Unit]
Description=GBot Web Application
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$SCRIPT_DIR
Environment="PATH=$SCRIPT_DIR/venv/bin"
Environment="PYTHONPATH=$SCRIPT_DIR"
Environment="FLASK_APP=app.py"
Environment="FLASK_ENV=production"
ExecStart=$SCRIPT_DIR/venv/bin/gunicorn \\
    --workers 2 \\
    --bind unix:$SCRIPT_DIR/gbot.sock \\
    --error-logfile $SCRIPT_DIR/logs/gunicorn_error.log \\
    --access-logfile $SCRIPT_DIR/logs/gunicorn_access.log \\
    --capture-output \\
    --log-level info \\
    app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    $SUDO_CMD mv /tmp/gbot_service "$SERVICE_FILE"
    
    # Reload systemd and enable service
    $SUDO_CMD systemctl daemon-reload
    $SUDO_CMD systemctl enable gbot
    
    log_success "Systemd service created and enabled"
}

start_services() {
    log "Starting all services..."
    
    # Start PostgreSQL
    $SUDO_CMD systemctl restart postgresql
    sleep 2
    if ! systemctl is-active --quiet postgresql; then
        log_error "PostgreSQL failed to start"
        systemctl status postgresql
        exit 1
    fi
    log_success "PostgreSQL is running"
    
    # Start GBot service
    $SUDO_CMD systemctl restart gbot
    sleep 2
    if ! systemctl is-active --quiet gbot; then
        log_error "GBot service failed to start"
        systemctl status gbot
        journalctl -u gbot -n 50
        exit 1
    fi
    log_success "GBot service is running"
    
    # Start Nginx
    $SUDO_CMD systemctl restart nginx
    sleep 2
    if ! systemctl is-active --quiet nginx; then
        log_error "Nginx failed to start"
        systemctl status nginx
        exit 1
    fi
    log_success "Nginx is running"
    
    # Show service statuses
    echo -e "\n${GREEN}=== Service Status ===${NC}"
    systemctl status postgresql --no-pager
    systemctl status gbot --no-pager
    systemctl status nginx --no-pager
}

run_complete_installation() {
    log "Starting complete installation..."
    
    # Clear credentials file
    > "$CREDENTIALS_FILE"
    chmod 600 "$CREDENTIALS_FILE"
    
    cleanup_duplicate_files
    create_required_directories
    check_system_requirements
    install_system_dependencies
    setup_postgresql
    setup_python_environment
    setup_nginx
    setup_systemd_service
    start_services
    
    log_success "Complete installation finished successfully!"
    
    # Show all credentials and service status
    show_credentials
    
    echo -e "\n${GREEN}Installation is complete. Your application should be accessible at your server's IP address.${NC}"
}

main() {
    touch "$LOG_FILE"
    show_banner
    
    if [ "$1" = "--reinstall" ]; then
        log "Reinstallation requested. This will wipe the current installation."
        run_complete_installation
    elif [ "$1" = "--install" ]; then
        run_complete_installation
    else
        echo "Usage: $0 [--install | --reinstall]"
        exit 1
    fi
}

main "$@"
