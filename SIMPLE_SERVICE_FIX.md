# Simplest Gunicorn Service Fix

Since you're encountering permission issues with the service, here's an even simpler approach that will work immediately:

## Use the Simple Service File (Root User)

1. Copy the simplified service file to the right location:
   ```bash
   sudo cp gunicorn.simple.service /etc/systemd/system/gbot.service
   ```

2. This service file:
   - Runs as root (no permission issues)
   - Logs to /var/log (standard location)
   - Has minimal configuration

3. Reload systemd and restart the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart gbot
   ```

4. Check the service status:
   ```bash
   sudo systemctl status gbot
   ```

## Why This Works

The simple approach works because:

1. Running as root eliminates all permission problems
2. Using standard system log locations avoids directory creation issues
3. Simplifies the configuration to focus on getting it running

## Security Note

In production environments, you'd typically want to avoid running services as root. However, for getting things running initially, this approach is much simpler. You can refine the permissions later once everything is working.

## Checking the Logs

You can monitor the logs with:

```bash
sudo tail -f /var/log/gbot-error.log
sudo tail -f /var/log/gbot-access.log
```

## Testing the Website

Once the service is running, open your browser and visit:

```
http://YOUR_SERVER_IP/
```

If you're on a local machine, just use:

```
http://localhost/
```

## Checking API Health

You can verify the API is working with:

```bash
curl http://localhost:5000/api/health
```

This should return a JSON response with "status": "healthy"
