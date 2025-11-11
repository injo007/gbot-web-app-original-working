## Brief overview
Guidelines for full-stack development and deployment practices, focusing on secure, production-grade solutions with emphasis on maintaining existing functionality while modernizing infrastructure.

## Development workflow
- Always preserve existing functionality when upgrading or modernizing components
- Use TypeScript for frontend development with strict type checking enabled
- Implement changes iteratively with proper error handling and rollback mechanisms
- Maintain backward compatibility with existing APIs and routes
- Keep original endpoint URLs and request/response contracts unchanged
- Use environment variables for configuration and secrets

## Architecture patterns
- Separate frontend and backend concerns while maintaining tight integration
- Frontend: React 18+ with Redux Toolkit for state management
- Backend: Flask with proper WSGI/proxy configuration
- Use proxy configuration to handle API routing seamlessly
- Implement health check endpoints for monitoring
- Structure frontend with feature-based organization (components, pages, store)

## Deployment strategy
- Support dual-environment deployment (Windows dev, Ubuntu prod)
- Implement proper Nginx configuration with security headers
- Use systemd services for process management on Ubuntu
- Include comprehensive deployment verification steps
- Maintain backup mechanisms for critical files
- Handle cross-platform path and permission differences

## Error handling
- Implement proper error boundaries in React components
- Add health check endpoints for monitoring
- Include rollback mechanisms for failed deployments
- Maintain detailed logging for troubleshooting
- Handle edge cases in file operations and permissions

## Security practices
- Implement proper CSRF protection
- Use secure headers in Nginx configuration
- Implement role-based access control
- Sanitize all user inputs
- Use HTTPS in production
- Follow principle of least privilege for file permissions

## Testing and quality assurance
- Implement health checks for critical services
- Add comprehensive deployment verification steps
- Test cross-platform compatibility (Windows/Ubuntu)
- Verify API integrations and proxy configurations
- Include rollback procedures for failed deployments
- Test with production-like data and configurations

## Code organization
- Use feature-based directory structure
- Implement clean separation of concerns
- Maintain consistent file naming conventions
- Keep configuration separate from application code
- Use TypeScript for better type safety
