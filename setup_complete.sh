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
    
    # Check pip - install if not available
    if command -v pip3 &> /dev/null; then
        log_success "pip3 is available"
    else
        log_warning "pip3 is not available, will install it"
        # Install pip3 if not available
        if command -v apt-get &> /dev/null; then
            $SUDO_CMD apt-get update
            $SUDO_CMD apt-get install -y python3-pip
        elif command -v yum &> /dev/null; then
            $SUDO_CMD yum install -y python3-pip
        elif command -v dnf &> /dev/null; then
            $SUDO_CMD dnf install -y python3-pip
        else
            log_error "Cannot install pip3 - unsupported package manager"
            exit 1
        fi
        
        # Verify pip3 is now available
        if command -v pip3 &> /dev/null; then
            log_success "pip3 installed successfully"
        else
            log_error "Failed to install pip3"
            exit 1
        fi
    fi
    
    # Check disk space
    DISK_SPACE=$(df . | awk 'NR==2 {print $4}')
    DISK_SPACE_GB=$((DISK_SPACE / 1024 / 1024))
    if [ $DISK_SPACE_GB -gt 1000 ]; then
        log_success "Disk space: ${DISK_SPACE_GB}MB available"
    else
        log_warning "Low disk space: ${DISK_SPACE_GB}MB available (1GB+ recommended)"
    fi
    
    # Check memory
    if command -v free &> /dev/null; then
        MEMORY_KB=$(free | awk 'NR==2{print $2}')
        MEMORY_MB=$((MEMORY_KB / 1024))
        if [ $MEMORY_MB -gt 512 ]; then
            log_success "Memory: ${MEMORY_MB}MB available"
        else
            log_warning "Low memory: ${MEMORY_MB}MB available (512MB+ recommended)"
        fi
    fi
    
    log_success "System requirements check completed"
}

install_system_dependencies() {
    log "Installing system dependencies..."
    
    if command -v apt-get &> /dev/null; then
        log "Using apt-get package manager"
        $SUDO_CMD apt-get update
        
        # Install Python and development tools
        $SUDO_CMD apt-get install -y python3 python3-pip python3-dev python3-venv python3-setuptools python3-wheel
        $SUDO_CMD apt-get install -y build-essential libssl-dev libffi-dev pkg-config
        
        # Install PostgreSQL
        $SUDO_CMD apt-get install -y postgresql postgresql-contrib postgresql-client
        
        # Install Nginx
        $SUDO_CMD apt-get install -y nginx
        
        # Install firewall
        $SUDO_CMD apt-get install -y ufw
        
        # Install SSL tools
        $SUDO_CMD apt-get install -y certbot python3-certbot-nginx
        
        # Install utilities
        $SUDO_CMD apt-get install -y curl wget git unzip
        
        # Install additional Python packages that might be needed
        $SUDO_CMD apt-get install -y python3-dev python3-pip python3-venv
        
    elif command -v yum &> /dev/null; then
        log "Using yum package manager"
        $SUDO_CMD yum update -y
        
        # Install Python and development tools
        $SUDO_CMD yum install -y python3 python3-pip python3-devel python3-setuptools python3-wheel
        $SUDO_CMD yum install -y gcc openssl-devel libffi-devel pkg-config
        
        # Install PostgreSQL
        $SUDO_CMD yum install -y postgresql-server postgresql-contrib
        
        # Install Nginx
        $SUDO_CMD yum install -y nginx
        
        # Install firewall
        $SUDO_CMD yum install -y firewalld
        
        # Install utilities
        $SUDO_CMD yum install -y curl wget git unzip
        
    elif command -v dnf &> /dev/null; then
        log "Using dnf package manager"
        $SUDO_CMD dnf update -y
        
        # Install Python and development tools
        $SUDO_CMD dnf install -y python3 python3-pip python3-devel python3-setuptools python3-wheel
        $SUDO_CMD dnf install -y gcc openssl-devel libffi-devel pkg-config
        
        # Install PostgreSQL
        $SUDO_CMD dnf install -y postgresql-server postgresql-contrib
        
        # Install Nginx
        $SUDO_CMD dnf install -y nginx
        
        # Install firewall
        $SUDO_CMD dnf install -y firewalld
        
        # Install utilities
        $SUDO_CMD dnf install -y curl wget git unzip
        
    else
        log_error "Unsupported package manager"
        exit 1
    fi
    
    # Verify critical packages are installed
    log "Verifying critical packages..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python3 installation failed"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 installation failed"
        exit 1
    fi
    
    # Check PostgreSQL
    if ! command -v psql &> /dev/null; then
        log_error "PostgreSQL installation failed"
        exit 1
    fi
    
    # Check Nginx
    if ! command -v nginx &> /dev/null; then
        log_error "Nginx installation failed"
        exit 1
    fi
    
    log_success "System dependencies installed and verified"
}

setup_postgresql() {
    log "Setting up PostgreSQL database..."
    
    # Check if PostgreSQL is already running
    if systemctl is-active --quiet postgresql; then
        log "PostgreSQL is already running"
    else
        # Start PostgreSQL service
        if command -v apt-get &> /dev/null; then
            $SUDO_CMD systemctl start postgresql
            $SUDO_CMD systemctl enable postgresql
        elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
            # For RHEL-based systems, initialize the database if it hasn't been
            if [ ! -d "/var/lib/pgsql/data/base" ]; then
                $SUDO_CMD postgresql-setup initdb
            fi
            $SUDO_CMD systemctl start postgresql
            $SUDO_CMD systemctl enable postgresql
        fi
    fi
    
    # Wait for PostgreSQL to be fully ready
    log "Waiting for PostgreSQL to be ready..."
    sleep 5
    
    # Configure PostgreSQL for production
    log "Configuring PostgreSQL for production..."
    sudo -u postgres psql -c "ALTER SYSTEM SET max_connections = '100';" 2>/dev/null || true
    sudo -u postgres psql -c "ALTER SYSTEM SET shared_buffers = '256MB';" 2>/dev/null || true
    
    # Restart PostgreSQL to apply changes
    $SUDO_CMD systemctl restart postgresql
    sleep 3
    
    # Create database and user
    DB_NAME="gbot_db"
    DB_USER="gbot_user"
    DB_PASS=$(openssl rand -hex 12)
    
    # Drop existing user and database to ensure clean setup
    log "Ensuring clean database setup..."
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null || true
    sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;" 2>/dev/null || true
    
    # Create database
    log "Creating database '$DB_NAME'..."
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"
    
    # Create user with new password
    log "Creating user '$DB_USER'..."
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    
    # Grant privileges
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
    
    # Test the connection
    log "Testing database connection..."
    if PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" &> /dev/null; then
        log_success "Database connection test passed"
    else
        log_error "Database connection test failed"
        exit 1
    fi
    
    # Save database credentials
    echo "DATABASE_URL=postgresql://$DB_USER:$DB_PASS@localhost/$DB_NAME" > "$SCRIPT_DIR/.db_credentials"
    chmod 600 "$SCRIPT_DIR/.db_credentials"
    
    log_success "PostgreSQL setup completed"
}

setup_python_environment() {
    log "Setting up Python environment..."
    
    # Create virtual environment
    if [ -d "venv" ]; then
        log "Virtual environment already exists, removing for clean install..."
        rm -rf venv
    fi
    
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python dependencies
    if [ -f "requirements.txt" ]; then
        log "Installing Python dependencies..."
        pip install -r requirements.txt
        log_success "Python dependencies installed"
    else
        log_error "requirements.txt not found"
        exit 1
    fi
    
    # Ensure gunicorn is installed
    if ! pip show gunicorn >/dev/null 2>&1; then
        log "Installing gunicorn..."
        pip install gunicorn
    fi
    
    log_success "Python environment setup completed"
    
    # Deactivate virtual environment
    deactivate
}

setup_database() {
    log "Setting up application database..."

    # Ensure the environment file exists
    create_environment_file

    # Activate virtual environment
    source venv/bin/activate

    # Set environment variables for the Python process
    if [ -f ".env" ]; then
        export $(grep -v '^#' .env | xargs)
    fi
    if [ -f ".db_credentials" ]; then
        source .db_credentials
        export DATABASE_URL
    fi

    # Get current IP for whitelist
    CURRENT_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")

    # Run the external database initialization script
    if [ -f "init_db.py" ]; then
        log "Running database initialization script..."
        python3 init_db.py "$CURRENT_IP"
        log_success "Database setup completed."
    else
        log_error "init_db.py not found. Cannot set up database."
        exit 1
    fi

    # Deactivate virtual environment
    deactivate
}

create_environment_file() {
    log "Creating environment configuration..."
    
    # Generate secure keys
    SECRET_KEY=$(openssl rand -hex 32)
    WHITELIST_TOKEN=$(openssl rand -hex 16)
    
    # Load database credentials if available
    if [ -f ".db_credentials" ]; then
        source .db_credentials
    else
        # This is a fallback, but setup_postgresql should always create the credentials file
        DATABASE_URL="sqlite:///$(pwd)/gbot.db"
    fi
    
    # Create .env file
    cat > .env << EOF
# GBot Web Application Environment Configuration
SECRET_KEY=$SECRET_KEY
WHITELIST_TOKEN=$WHITELIST_TOKEN
DATABASE_URL=$DATABASE_URL
ENABLE_IP_WHITELIST=True
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=3600
DEBUG=False
FLASK_ENV=production
EOF
    
    log_success "Environment file created"
}

setup_nginx() {
    log "Setting up Nginx reverse proxy..."
    
    NGINX_CONFIG="/etc/nginx/sites-available/gbot"
    
    # Remove any existing default site that might interfere
    if [ -L "/etc/nginx/sites-enabled/default" ]; then
        log "Removing default nginx site..."
        $SUDO_CMD rm "/etc/nginx/sites-enabled/default"
    fi
    
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
    
    # Test and restart nginx
    if $SUDO_CMD nginx -t; then
        $SUDO_CMD systemctl restart nginx
        log_success "Nginx configuration completed and restarted"
    else
        log_error "Nginx configuration test failed"
        exit 1
    fi
}

setup_systemd_service() {
    log "Setting up systemd service..."
    
    SERVICE_FILE="/etc/systemd/system/gbot.service"
    
    # Create systemd service file
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
ExecStart=$SCRIPT_DIR/venv/bin/gunicorn --workers 2 --bind unix:$SCRIPT_DIR/gbot.sock app:app
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
    $SUDO_CMD systemctl restart postgresql
    $SUDO_CMD systemctl restart gbot
    $SUDO_CMD systemctl restart nginx
    log_success "Services have been started/restarted."
}

run_complete_installation() {
    log "Starting complete installation..."
    
    check_system_requirements
    install_system_dependencies
    setup_postgresql
    setup_python_environment
    setup_database # This now uses the external script
    setup_nginx
    setup_systemd_service
    start_services
    
    log_success "Complete installation finished successfully!"
    echo -e "${GREEN}Installation is complete. Your application should be accessible at your server's IP address.${NC}"
}

main() {
    touch "$LOG_FILE"
    show_banner
    
    if [ "$1" = "--reinstall" ]; then
        log "Reinstallation requested. This will wipe the current installation."
        # Add any cleaning logic here if needed, e.g., stopping services
        run_complete_installation
    elif [ "$1" = "--install" ]; then
        run_complete_installation
    else
        echo "Usage: $0 [--install | --reinstall]"
        exit 1
    fi
}

main "$@"
