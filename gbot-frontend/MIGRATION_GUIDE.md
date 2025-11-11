# Migration Guide: Deploying New Frontend on Ubuntu Server

This guide explains how to replace the old Flask templates with the new React frontend on your Ubuntu server.

## 1. Backup Current Application

First, let's backup the current application:

```bash
# SSH into your server
ssh user@your-server

# Create backup of current application
cd /var/www/gbot-web-app
sudo tar -czf ~/gbot-backup-$(date +%Y%m%d).tar.gz .
```

## 2. Build New Frontend Locally

On your development machine:

```bash
# Build the frontend
cd gbot-frontend
npm install
npm run build

# The build output will be in the dist/ directory
```

## 3. Update Flask Application

1. Modify Flask's `app.py` to serve the React frontend:

```python
# At the top of app.py
import os
from flask import send_from_directory

# Add this route at the end of app.py
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')
```

## 4. Deploy New Frontend

1. Stop the services:
```bash
sudo systemctl stop nginx
sudo systemctl stop gbot
```

2. Clear old static files:
```bash
# Backup old templates and static files
sudo mv /var/www/gbot-web-app/templates /var/www/gbot-web-app/templates.bak
sudo mv /var/www/gbot-web-app/static /var/www/gbot-web-app/static.bak

# Create new static directory
sudo mkdir -p /var/www/gbot-web-app/static
```

3. Upload new frontend files:
```bash
# From your local machine, in the gbot-frontend directory
scp -r dist/* user@your-server:/tmp/new-frontend/

# On the server
sudo cp -r /tmp/new-frontend/* /var/www/gbot-web-app/static/
sudo chown -R www-data:www-data /var/www/gbot-web-app/static
```

## 5. Update Nginx Configuration

1. Update your Nginx configuration:
```bash
sudo nano /etc/nginx/nginx.conf
```

2. Replace or update the server block:
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # Root directory for static files
    root /var/www/gbot-web-app/static;
    index index.html;

    # API proxy
    location /api/ {
        proxy_pass http://localhost:5000/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # Serve static files
    location / {
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache";
    }
}
```

## 6. Restart Services

```bash
# Test Nginx configuration
sudo nginx -t

# If test passes, restart services
sudo systemctl restart nginx
sudo systemctl restart gbot

# Check service status
sudo systemctl status nginx
sudo systemctl status gbot
```

## 7. Clear Browser Cache

Since you're upgrading from the old interface to the new one, it's important to clear your browser cache:

1. Open Chrome/Firefox
2. Press Ctrl+Shift+Delete
3. Select "All time" for time range
4. Check "Cached images and files"
5. Click "Clear data"
6. Close all browser windows
7. Open a new browser window
8. Navigate to your application URL

## 8. Verify Deployment

1. Check application logs:
```bash
# Nginx logs
sudo tail -f /var/log/nginx/error.log
sudo tail -f /var/log/nginx/access.log

# Flask application logs
sudo journalctl -u gbot -f
```

2. Test key functionality:
- Login page should show new design
- Dashboard should load with new UI
- All API calls should work
- User management should function
- Domain management should work
- IP whitelist should be operational

## 9. Troubleshooting

If you still see the old interface:

1. Verify static files:
```bash
# Check if new files exist
ls -la /var/www/gbot-web-app/static/

# Verify index.html exists
cat /var/www/gbot-web-app/static/index.html
```

2. Check Nginx configuration:
```bash
# Verify Nginx is using correct configuration
sudo nginx -T | grep root
sudo nginx -T | grep "location /"
```

3. Clear server-side cache:
```bash
# Clear Nginx cache
sudo rm -rf /var/cache/nginx/*
sudo systemctl restart nginx
```

4. Check file permissions:
```bash
# Ensure proper ownership
sudo chown -R www-data:www-data /var/www/gbot-web-app/static

# Ensure proper permissions
sudo chmod -R 755 /var/www/gbot-web-app/static
```

5. Force reload without cache:
```bash
# In Chrome:
1. Open Developer Tools (F12)
2. Right-click on the refresh button
3. Select "Empty Cache and Hard Reload"
```

## 10. Rollback Procedure

If you need to revert to the old interface:

```bash
# Stop services
sudo systemctl stop nginx
sudo systemctl stop gbot

# Restore old files
sudo rm -rf /var/www/gbot-web-app/static
sudo rm -rf /var/www/gbot-web-app/templates
sudo mv /var/www/gbot-web-app/static.bak /var/www/gbot-web-app/static
sudo mv /var/www/gbot-web-app/templates.bak /var/www/gbot-web-app/templates

# Restore original app.py (from backup)
sudo tar -xzf ~/gbot-backup-*.tar.gz app.py
sudo mv app.py /var/www/gbot-web-app/app.py

# Restart services
sudo systemctl restart nginx
sudo systemctl restart gbot
```

## Need Help?

If you're still experiencing issues after following these steps, please:

1. Check the application logs
2. Verify all file permissions
3. Ensure all services are running
4. Contact the development team with:
   - Error messages from logs
   - Screenshot of the current interface
   - List of steps you've tried
   - Server environment details
