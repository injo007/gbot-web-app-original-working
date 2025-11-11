# Quick Start Guide for GBot on Ubuntu 22.04

This guide provides the quick start steps for deploying GBot on a fresh Ubuntu 22.04 server where you have already uploaded the project to `/opt/gbot-web-app-original-working`.

## Prerequisites

Ensure you have:
- Ubuntu 22.04 server
- Root or sudo access
- Project uploaded to `/opt/gbot-web-app-original-working`

## Step 1: Install Required System Dependencies

```bash
# Update system packages
sudo apt update
sudo apt upgrade -y

# Install Node.js 20.x (if not already installed)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install other required dependencies
sudo apt install -y git nginx python3 python3-pip python3-venv libssl-dev pkg-config libpq-dev
```

## Step 2: Set Up Python Environment and Backend

```bash
# Navigate to the project directory
cd /opt/gbot-web-app-original-working

# Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Initialize the database if needed
# If you have a database migration script, run it here
# python migrate_postgresql.py  # (If using PostgreSQL)
```

## Step 3: Frontend Deployment

```bash
# Make the enhanced setup script executable
chmod +x setup_complete_enhanced.sh

# Run the installation process
sudo ./setup_complete_enhanced.sh --install
```

This script will:
- Set up an 8GB swap file to prevent memory issues
- Remove old frontend files (templates directory)
- Set up the React frontend with memory optimizations
- Configure Nginx for SPA routing and API proxying
- Verify the deployment

## Step 4: Set Up System Service for Backend

Create a system service file to keep the Flask app running:

```bash
sudo nano /etc/systemd/system/gbot.service
```

Add the following content:

```ini
[Unit]
Description=GBot Web Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/gbot-web-app-original-working
Environment="PATH=/opt/gbot-web-app-original-working/venv/bin"
ExecStart=/opt/gbot-web-app-original-working/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable gbot
sudo systemctl start gbot
```

## Step 5: Configure Firewall (Optional)

If using UFW firewall:

```bash
sudo ufw allow 'Nginx Full'
sudo ufw status
```

## Step 6: Verify the Deployment

Check if everything is running properly:

```bash
# Check Nginx status
sudo systemctl status nginx

# Check GBot service status
sudo systemctl status gbot

# Verify Nginx configuration
sudo nginx -t

# Run the verification script
sudo ./setup_complete_enhanced.sh --verify
```

## Step 7: Access Your Application

Your application should now be accessible:
- Web interface: http://YOUR_SERVER_IP/
- API endpoint: http://YOUR_SERVER_IP/api/

## Troubleshooting

If you encounter issues:

1. Check Nginx logs:
   ```bash
   sudo tail -f /var/log/nginx/error.log
   ```

2. Check GBot service logs:
   ```bash
   sudo journalctl -u gbot -f
   ```

3. Verify the frontend files:
   ```bash
   ls -la /opt/gbot-web-app-original-working/static/
   ```

4. If the frontend is served but API calls fail, ensure the Flask app is running and configured correctly:
   ```bash
   curl http://localhost:5000/api/health
   ```

5. If you need to restart services:
   ```bash
   sudo systemctl restart nginx gbot
   ```
