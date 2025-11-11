# GBot Frontend Deployment Guide

This guide provides instructions for deploying the new React frontend to replace the old Flask templates. It addresses memory issues during build and ensures proper configuration for all components.

## Prerequisites

- Ubuntu Server (tested on 22.04 LTS)
- Node.js 20.x or newer
- Nginx
- Python 3.10+ with Flask
- sudo/root access

## Files Included

| File | Purpose |
|------|---------|
| `optimize_frontend_build.sh` | Script to build the frontend with memory optimizations |
| `verify_frontend_deployment.sh` | Script to verify the frontend deployment |
| `vite.config.optimized.ts` | Memory-optimized Vite configuration |
| `nginx.simplified.conf` | Simplified Nginx configuration |

## Issue Overview

The frontend deployment faces several challenges:

1. **Memory Issues**: The build process is killed due to insufficient memory
2. **Incomplete Cleanup**: Old frontend files (templates) remain and conflict
3. **Configuration Issues**: Nginx and Flask need proper SPA configuration 
4. **Integration Problems**: API routes may be misconfigured

## Deployment Process

### Step 1: Prepare Environment

Make the scripts executable (on Linux/Ubuntu):

```bash
chmod +x optimize_frontend_build.sh verify_frontend_deployment.sh
```

Note: On Windows, you don't need to make scripts executable. When deploying to the production Ubuntu server, remember to run this command there.

### Step 2: Apply Optimized Configuration

Copy the optimized Vite configuration:

```bash
# From the project root
cp gbot-frontend/vite.config.optimized.ts gbot-frontend/vite.config.ts
```

### Step 3: Build the Frontend

Run the optimization script with sudo (for swap file creation):

```bash
sudo ./optimize_frontend_build.sh
```

This script:
- Creates a 4GB swap file to prevent memory issues
- Removes old frontend files
- Optimizes the build process
- Copies built files to the static directory

### Step 4: Configure Nginx

Copy the simplified configuration to Nginx:

```bash
sudo cp gbot-frontend/nginx.simplified.conf /etc/nginx/sites-available/gbot
sudo ln -s /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default  # Optional: remove default site
sudo nginx -t  # Test the configuration
sudo systemctl restart nginx
```

### Step 5: Restart Services

```bash
sudo systemctl restart gbot
sudo systemctl restart nginx
```

### Step 6: Verify Deployment

Run the verification script:

```bash
sudo ./verify_frontend_deployment.sh
```

This script checks:
- Static files existence
- Removal of old templates
- Nginx configuration
- Flask configuration
- Network connectivity
- Service status

## Troubleshooting

### Problem: Build Still Fails with "Killed"

Solution:
1. Try increasing the swap size in `optimize_frontend_build.sh`:
   ```bash
   # Change from 4GB to 8GB
   sudo fallocate -l 8G "$SWAP_FILE"
   ```
2. Use the lowest memory build option:
   ```bash
   NODE_OPTIONS="--max-old-space-size=2048" npx vite build --mode development --minify false
   ```

### Problem: SPA Routes Return 404

Solution:
1. Verify Nginx configuration has:
   ```
   location / {
       try_files $uri $uri/ /index.html;
   }
   ```
2. Ensure Flask has fallback routes:
   ```python
   @app.route('/', defaults={'path': ''})
   @app.route('/<path:path>')
   def serve(path):
       return send_from_directory(app.static_folder, 'index.html')
   ```

### Problem: API Calls Fail

Solution:
1. Check proxy configuration in Nginx:
   ```
   location /api/ {
       proxy_pass http://localhost:5000/api/;
   }
   ```
2. Verify backend routes start with `/api/`
3. Check CORS settings in Flask app

### Problem: Old Templates Still Active

Solution:
1. Force remove templates directory:
   ```bash
   sudo rm -rf /opt/gbot-web-app-original-working/templates
   ```
2. Remove template imports from Flask:
   ```bash
   sed -i '/render_template/d' app.py
   ```

## Completeness Checklist

- [ ] Frontend builds without "Killed" error
- [ ] Static directory has index.html and asset files
- [ ] Old templates directory is removed
- [ ] Nginx is configured for SPA routing
- [ ] API proxy is working
- [ ] All pages load without 404 errors
- [ ] Login, user management, and settings are functional
- [ ] Domain management works correctly
- [ ] Whitelist functionality works

## Differences From Old Frontend

The new React frontend offers several improvements:

1. **Modern Architecture**: Uses React, Redux, and modern JS patterns
2. **Better State Management**: Uses Redux for centralized state
3. **Improved Performance**: Optimized bundle size and caching
4. **Enhanced User Experience**: More reactive UI with better feedback
5. **Maintainable Code**: TypeScript for type safety
6. **Better Error Handling**: Consistent error boundaries and feedback

All original features have been preserved with the same functionality but improved UX.

## Verifying Features

To ensure original functionality works:

1. **Login**: Try logging in and check authentication persistence
2. **Dashboard**: Verify stats and information match old system
3. **User Management**: Add, edit, and remove users
4. **Domain Management**: Verify domain status changes and bulk operations
5. **Whitelist**: Check IP whitelist functionality
6. **Settings**: Verify all settings can be updated

## Additional Notes

- The new frontend uses the same API endpoints as the old system
- Backend API routes starting with `/api/` are retained for compatibility
- File structure follows modern React conventions
- The frontend is responsive and works on mobile devices

If you experience any issues, run the verification script first to identify the problem area, then consult the troubleshooting section of this guide.
