# GBot Web App Automated Installation

This guide explains how to use the automated installation script to set up the GBot Web App on an Ubuntu server.

> **IMPORTANT**: Before uploading to your Ubuntu server, make sure to run `git update-index --chmod=+x install_gbot.sh cleanup_unused_files.sh` on your local machine to ensure the scripts will be marked as executable when cloned or unpacked on the server.

## Before You Begin

Ensure you have:
- Ubuntu 22.04 server
- Root or sudo access
- Project uploaded to `/opt/gbot-web-app-original-working`

## Installation Steps

1. **Make the scripts executable** (on Ubuntu):
   ```bash
   sudo chmod +x install_gbot.sh cleanup_unused_files.sh
   ```

2. **Run the installation script** as root:
   ```bash
   sudo ./install_gbot.sh
   ```

## What the Installation Script Does

The script will automatically:

1. Install system dependencies (Node.js, Nginx, Python packages)
2. Set up a Python virtual environment and install requirements
3. Build the React frontend with memory optimizations
4. Configure Nginx for SPA routing
5. Set up the Gunicorn service as root user
6. Clean up unnecessary files
7. Verify the installation
8. Clean up unnecessary files

## After Installation

Once the installation completes successfully, you should see verification results and a URL to access your application.

Access the application at: `http://YOUR_SERVER_IP/`

## Troubleshooting

If you encounter issues:

1. Check Nginx logs:
   ```bash
   sudo tail -f /var/log/nginx/error.log
   ```

2. Check Gunicorn service logs:
   ```bash
   sudo journalctl -u gbot -f
   ```

3. Verify the frontend files:
   ```bash
   ls -la /opt/gbot-web-app-original-working/static/
   ```

4. Test API health:
   ```bash
   curl http://localhost:5000/api/health
   ```

5. Restart services if needed:
   ```bash
   sudo systemctl restart gbot nginx
   ```

## Post-Installation Security Hardening

After verifying that everything works, you may want to consider:

1. Setting up HTTPS with Let's Encrypt
2. Adding firewall rules with ufw
3. Creating a dedicated user instead of running as root

## Cleanup

If you still have old installation files present, you can remove them with:

```bash
sudo ./cleanup_unused_files.sh
```

This will clean up all the old files that are no longer needed, leaving only the consolidated installation script and this documentation.
