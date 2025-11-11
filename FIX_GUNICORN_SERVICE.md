# Fixing the Gunicorn Service Error

The logs show that your gunicorn service is failing with the error:
```
Error: 'logs/gunicorn_error.log' isn't writable [FileNotFoundError(2, 'No such file or directory')]
```

This means the logs directory doesn't exist. Here's how to fix it:

## Option 1: Replace the Service File

1. Copy the fixed service file to the right location:
   ```bash
   sudo cp gunicorn.fixed.service /etc/systemd/system/gbot.service
   ```

2. Reload systemd, then restart the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart gbot
   ```

3. Check the service status:
   ```bash
   sudo systemctl status gbot
   ```

## Option 2: Manual Fix

If you prefer to modify the existing file:

1. Edit the service file:
   ```bash
   sudo nano /etc/systemd/system/gbot.service
   ```

2. Make sure the file has the following content:
   ```ini
   [Unit]
   Description=GBot Web Application
   After=network.target

   [Service]
   User=www-data
   Group=www-data
   WorkingDirectory=/opt/gbot-web-app-original-working
   Environment="PATH=/opt/gbot-web-app-original-working/venv/bin"
   # Create logs directory first
   ExecStartPre=/bin/mkdir -p /opt/gbot-web-app-original-working/logs
   # Set proper permissions for logs directory
   ExecStartPre=/bin/chown -R www-data:www-data /opt/gbot-web-app-original-working/logs
   # Start gunicorn with direct log output
   ExecStart=/opt/gbot-web-app-original-working/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 --error-logfile - --access-logfile - app:app
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

3. Save the file, reload systemd, and restart the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart gbot
   ```

## Verify Everything is Working

After fixing the service, check that both components are running:

```bash
# Check Nginx status
sudo systemctl status nginx

# Check GBot service status
sudo systemctl status gbot
```

You should now be able to access your application at `http://YOUR_SERVER_IP/`

## Notes

- The CSS warning during verification is expected and can be ignored - this app uses CSS-in-JS (Emotion) instead of separate CSS files
- The application should be fully functional once the gunicorn service is running
