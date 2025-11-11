# Ubuntu Deployment Guide for GBot Web App

This guide explains how to deploy the GBot Web App on an Ubuntu server.

## Prerequisites

- Ubuntu 20.04 LTS or newer
- Root access or sudo privileges
- Domain name pointing to your server (for SSL)

## 1. Initial Server Setup

```bash
# Update system packages
sudo apt update
sudo apt upgrade -y

# Install required packages
sudo apt install -y nginx certbot python3-certbot-nginx ufw

# Configure firewall
sudo ufw allow 'Nginx Full'
sudo ufw allow OpenSSH
sudo ufw enable
```

## 2. Install Node.js and npm

```bash
# Add NodeSource repository
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -

# Install Node.js and npm
sudo apt install -y nodejs

# Verify installation
node --version
npm --version
```

## 3. Install PM2 Process Manager

```bash
# Install PM2 globally
sudo npm install -g pm2

# Enable PM2 startup script
sudo pm2 startup systemd
```

## 4. Configure SSL with Let's Encrypt

```bash
# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

## 5. Clone and Build Application

```bash
# Create application directory
sudo mkdir -p /var/www/gbot-web-app
sudo chown -R $USER:$USER /var/www/gbot-web-app

# Clone repository
git clone https://github.com/your-repo/gbot-web-app.git /var/www/gbot-web-app
cd /var/www/gbot-web-app

# Install dependencies
npm install

# Build application
npm run build
```

## 6. Configure Nginx

1. Copy the provided nginx.conf:
```bash
sudo cp nginx.conf /etc/nginx/nginx.conf
```

2. Update SSL certificate paths in nginx.conf:
```nginx
ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
```

3. Test and restart Nginx:
```bash
sudo nginx -t
sudo systemctl restart nginx
```

## 7. Set Up Flask Backend

1. Install Python dependencies:
```bash
sudo apt install -y python3-pip python3-venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Configure Gunicorn:
```bash
sudo nano /etc/systemd/system/gbot.service
```

Add the following content:
```ini
[Unit]
Description=GBot Web App
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/gbot-web-app
Environment="PATH=/var/www/gbot-web-app/venv/bin"
ExecStart=/var/www/gbot-web-app/venv/bin/gunicorn --workers 4 --bind 127.0.0.1:5000 app:app

[Install]
WantedBy=multi-user.target
```

3. Start and enable the service:
```bash
sudo systemctl start gbot
sudo systemctl enable gbot
```

## 8. Environment Configuration

1. Create production environment file:
```bash
sudo nano /var/www/gbot-web-app/.env.production
```

2. Add required environment variables:
```env
VITE_API_BASE_URL=/api
VITE_APP_ENVIRONMENT=production
```

## 9. Security Considerations

1. Set up fail2ban:
```bash
sudo apt install -y fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo systemctl restart fail2ban
```

2. Configure additional security headers in Nginx (already included in nginx.conf)

3. Regular system updates:
```bash
# Create auto-update script
sudo nano /etc/cron.weekly/auto-updates
```

Add the following content:
```bash
#!/bin/bash
apt update
apt upgrade -y
apt autoremove -y
```

Make it executable:
```bash
sudo chmod +x /etc/cron.weekly/auto-updates
```

## 10. Monitoring and Maintenance

1. Set up log rotation:
```bash
sudo nano /etc/logrotate.d/gbot
```

Add the following content:
```
/var/log/gbot/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
    sharedscripts
    postrotate
        systemctl reload gbot
    endscript
}
```

2. Monitor application logs:
```bash
# Flask application logs
sudo tail -f /var/log/gbot/app.log

# Nginx access logs
sudo tail -f /var/log/nginx/access.log

# Nginx error logs
sudo tail -f /var/log/nginx/error.log
```

## 11. Backup Configuration

1. Create backup script:
```bash
sudo nano /usr/local/bin/backup-gbot
```

Add the following content:
```bash
#!/bin/bash
BACKUP_DIR="/var/backups/gbot"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup application files
tar -czf "$BACKUP_DIR/app_$DATE.tar.gz" /var/www/gbot-web-app

# Backup Nginx configuration
cp /etc/nginx/nginx.conf "$BACKUP_DIR/nginx_$DATE.conf"

# Backup SSL certificates
tar -czf "$BACKUP_DIR/ssl_$DATE.tar.gz" /etc/letsencrypt

# Remove backups older than 30 days
find "$BACKUP_DIR" -type f -mtime +30 -delete
```

Make it executable:
```bash
sudo chmod +x /usr/local/bin/backup-gbot
```

2. Add to crontab:
```bash
sudo crontab -e
```

Add the following line:
```
0 2 * * * /usr/local/bin/backup-gbot
```

## 12. Troubleshooting

### Common Issues

1. 502 Bad Gateway
- Check if Flask application is running:
```bash
sudo systemctl status gbot
```
- Check Gunicorn logs:
```bash
sudo journalctl -u gbot
```

2. SSL Certificate Issues
- Renew certificates:
```bash
sudo certbot renew
```
- Check certificate status:
```bash
sudo certbot certificates
```

3. Permission Issues
- Fix ownership:
```bash
sudo chown -R www-data:www-data /var/www/gbot-web-app
```
- Fix permissions:
```bash
sudo chmod -R 755 /var/www/gbot-web-app
```

### Performance Optimization

1. Enable Nginx caching:
```bash
sudo mkdir -p /var/cache/nginx
sudo chown -R www-data:www-data /var/cache/nginx
```

2. Optimize Gunicorn workers:
```bash
# Number of workers = (2 * CPU cores) + 1
sudo nano /etc/systemd/system/gbot.service
```

3. Monitor system resources:
```bash
sudo apt install -y htop
htop
```

## 13. Updating the Application

1. Create update script:
```bash
sudo nano /usr/local/bin/update-gbot
```

Add the following content:
```bash
#!/bin/bash
cd /var/www/gbot-web-app

# Pull latest changes
git pull

# Install dependencies
npm install

# Build application
npm run build

# Restart services
sudo systemctl restart gbot
sudo systemctl restart nginx
```

Make it executable:
```bash
sudo chmod +x /usr/local/bin/update-gbot
```

2. To update the application:
```bash
sudo /usr/local/bin/update-gbot
