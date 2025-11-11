#!/bin/bash

# GBot Frontend Deployment Verification Script
# This script checks that the frontend has been properly deployed and the old frontend removed
# It can be run after the frontend build and deployment to ensure everything is correct

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} Starting GBot frontend verification..."

# Configuration
APP_ROOT="/opt/gbot-web-app-original-working"
FRONTEND_DIR="$APP_ROOT/gbot-frontend"
STATIC_DIR="$APP_ROOT/static"
TEMPLATES_DIR="$APP_ROOT/templates"
NGINX_SITES="/etc/nginx/sites-enabled"
NGINX_CONFIG="/etc/nginx/sites-enabled/gbot"

# Check if we're running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}[!] This script should be run with sudo privileges for full verification${NC}"
  echo -e "${YELLOW}[!] Some checks might fail without proper permissions${NC}"
fi

# Header for report
echo -e "\n${YELLOW}═════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}          GBOT FRONTEND VERIFICATION REPORT          ${NC}"
echo -e "${YELLOW}═════════════════════════════════════════════════════${NC}\n"

echo -e "${BLUE}[1] Checking directory structure${NC}"

# Check if static directory exists and has files
if [ -d "$STATIC_DIR" ]; then
    echo -e "  ✅ Static directory exists: ${GREEN}PASS${NC}"
    
    # Check if static has files
    if [ "$(ls -A $STATIC_DIR)" ]; then
        echo -e "  ✅ Static directory has files: ${GREEN}PASS${NC}"
    else
        echo -e "  ❌ Static directory is empty: ${RED}FAIL${NC}"
    fi
    
    # Check for critical frontend files
    if [ -f "$STATIC_DIR/index.html" ]; then
        echo -e "  ✅ index.html exists: ${GREEN}PASS${NC}"
    else
        echo -e "  ❌ index.html missing: ${RED}FAIL${NC}"
    fi
    
    # Check for JavaScript files (main.js or similar)
    if ls $STATIC_DIR/assets/*.js &> /dev/null || ls $STATIC_DIR/*.js &> /dev/null; then
        echo -e "  ✅ JavaScript files exist: ${GREEN}PASS${NC}"
    else
        echo -e "  ❌ JavaScript files missing: ${RED}FAIL${NC}"
    fi
    
    # Check for CSS files
    if ls $STATIC_DIR/assets/*.css &> /dev/null || ls $STATIC_DIR/*.css &> /dev/null; then
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
else
    echo -e "  ✅ Old templates directory removed: ${GREEN}PASS${NC}"
fi

# Check nginx configuration
echo -e "\n${BLUE}[3] Checking Nginx configuration${NC}"

# Check if nginx is installed
if command -v nginx &> /dev/null; then
    echo -e "  ✅ Nginx installed: ${GREEN}PASS${NC}"
    
    # Check if sites-enabled exists
    if [ -d "$NGINX_SITES" ]; then
        echo -e "  ✅ Nginx sites-enabled directory exists: ${GREEN}PASS${NC}"
        
        # Check if gbot configuration is enabled
        if [ -f "$NGINX_CONFIG" ]; then
            echo -e "  ✅ GBot Nginx configuration exists: ${GREEN}PASS${NC}"
            
            # Check SPA configuration
            if grep -q "try_files.*index.html" "$NGINX_CONFIG"; then
                echo -e "  ✅ SPA routing configured: ${GREEN}PASS${NC}"
            else
                echo -e "  ❌ SPA routing not configured: ${RED}FAIL${NC}"
                echo -e "     Add 'try_files \$uri \$uri/ /index.html;' to the location / block"
            fi
            
            # Check API proxy
            if grep -q "proxy_pass.*5000" "$NGINX_CONFIG"; then
                echo -e "  ✅ API proxy configured: ${GREEN}PASS${NC}"
            else
                echo -e "  ❌ API proxy not configured: ${RED}FAIL${NC}"
            fi
        else
            echo -e "  ❌ GBot Nginx configuration missing: ${RED}FAIL${NC}"
        fi
    else
        echo -e "  ❌ Nginx sites-enabled directory missing: ${RED}FAIL${NC}"
    fi
else
    echo -e "  ❌ Nginx not installed: ${RED}FAIL${NC}"
fi

# Check Flask app
echo -e "\n${BLUE}[4] Checking Flask app configuration${NC}"

# Check if app.py exists
if [ -f "$APP_ROOT/app.py" ]; then
    echo -e "  ✅ Flask app exists: ${GREEN}PASS${NC}"
    
    # Check if render_template is removed or commented out
    if grep -q "render_template" "$APP_ROOT/app.py"; then
        echo -e "  ⚠️ render_template still in use: ${YELLOW}WARNING${NC}"
        echo -e "     This might indicate old template routes are still active"
    else
        echo -e "  ✅ No render_template found: ${GREEN}PASS${NC}"
    fi
    
    # Check for send_from_directory for SPA routing
    if grep -q "send_from_directory.*index.html" "$APP_ROOT/app.py"; then
        echo -e "  ✅ SPA routing in Flask configured: ${GREEN}PASS${NC}"
    else
        echo -e "  ⚠️ SPA routing in Flask not found: ${YELLOW}WARNING${NC}"
        echo -e "     Flask should serve index.html for any route not found"
    fi
else
    echo -e "  ❌ Flask app missing: ${RED}FAIL${NC}"
fi

# Verify the frontend-backend connection works
echo -e "\n${BLUE}[5] Performing network tests${NC}"

# Get local server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

# Test static file access
echo -ne "  Testing static file access... "
if curl -s -f --connect-timeout 5 "http://$SERVER_IP/index.html" > /dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# Test SPA routing
echo -ne "  Testing SPA routing... "
if curl -s -f --connect-timeout 5 "http://$SERVER_IP/dashboard" > /dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# Test API access
echo -ne "  Testing API access... "
if curl -s -f --connect-timeout 5 "http://$SERVER_IP/api/health" > /dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# Check services status
echo -e "\n${BLUE}[6] Checking service status${NC}"

# Check if gbot service is running
if systemctl is-active --quiet gbot; then
    echo -e "  ✅ GBot service is running: ${GREEN}PASS${NC}"
else
    echo -e "  ❌ GBot service is not running: ${RED}FAIL${NC}"
fi

# Check if nginx service is running
if systemctl is-active --quiet nginx; then
    echo -e "  ✅ Nginx service is running: ${GREEN}PASS${NC}"
else
    echo -e "  ❌ Nginx service is not running: ${RED}FAIL${NC}"
fi

# Summary
echo -e "\n${BLUE}[7] Summary${NC}"

# Create a simple error file if it doesn't exist yet
if [ ! -f "$STATIC_DIR/error.html" ]; then
    echo "<!DOCTYPE html>
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
</html>" > "$STATIC_DIR/error.html"
    echo -e "  ✅ Created fallback error page: ${GREEN}PASS${NC}"
fi

echo -e "\n${YELLOW}Frontend access URLs:${NC}"
echo -e "  Main app: ${BLUE}http://$SERVER_IP/${NC}"
echo -e "  Dashboard: ${BLUE}http://$SERVER_IP/dashboard${NC}"
echo -e "  API health check: ${BLUE}http://$SERVER_IP/api/health${NC}"

echo -e "\n${YELLOW}═════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}             VERIFICATION COMPLETE                    ${NC}"
echo -e "${YELLOW}═════════════════════════════════════════════════════${NC}\n"

echo -e "If any checks failed, please run the frontend optimization script again:"
echo -e "  ${BLUE}sudo bash optimize_frontend_build.sh${NC}"
echo -e "Then restart the services:"
echo -e "  ${BLUE}sudo systemctl restart gbot nginx${NC}"

exit 0
