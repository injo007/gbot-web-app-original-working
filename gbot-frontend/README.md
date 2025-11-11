# GBot Web App Frontend

Modern React + TypeScript frontend for the GBot Web App, providing a ClickUp-style interface for managing Google Workspace infrastructures.

## Features

- 🔐 Secure authentication with role-based access control
- 🌐 Multi-domain management
- 👥 User management with bulk operations
- 🛡️ IP whitelisting system
- ⚙️ System settings and configuration
- 📊 Real-time monitoring and statistics
- 🌓 Dark/Light theme support
- 📱 Responsive design

## Tech Stack

- React 18 with TypeScript
- Redux Toolkit + RTK Query for state management
- React Router v6 for navigation
- Emotion for styling
- Framer Motion for animations
- Vite for development and building

## Prerequisites

- Node.js >= 18.0.0
- npm >= 8.0.0
- A running instance of the GBot Flask backend

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/your-repo/gbot-web-app.git
cd gbot-web-app
```

2. Install dependencies:
```bash
npm install
```

3. Create a .env.local file (copy from .env.development):
```bash
cp .env.development .env.local
```

4. Start the development server:
```bash
npm run dev
```

The app will be available at http://localhost:3000

## Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Lint code
- `npm run format` - Format code with Prettier
- `npm run typecheck` - Check TypeScript types

### Project Structure

```
src/
├── api/           # API client configuration
├── components/    # Reusable UI components
├── layouts/       # Layout components
├── pages/         # Page components
├── store/         # Redux store configuration
│   ├── apis/     # RTK Query API definitions
│   └── slices/   # Redux slices
├── theme/         # Theme configuration
├── types/        # TypeScript type definitions
├── utils/        # Utility functions
├── App.tsx       # Root component
└── main.tsx      # Entry point
```

### Code Style

- Follow TypeScript best practices
- Use functional components with hooks
- Implement proper error handling
- Write meaningful comments
- Use consistent naming conventions

## Building for Production

1. Update environment variables in `.env.production`

2. Build the application:
```bash
npm run build
```

3. Test the production build:
```bash
npm run preview
```

## Deployment

See [UBUNTU_DEPLOYMENT.md](./UBUNTU_DEPLOYMENT.md) for detailed deployment instructions.

### Quick Deployment Steps

1. Build the application
2. Copy dist files to server
3. Configure Nginx
4. Set up SSL certificates
5. Start the application

## Security

- All API requests are made over HTTPS
- Authentication using secure cookies
- CSRF protection
- Content Security Policy headers
- IP whitelisting for access control

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

### Commit Message Format

```
type(scope): subject

body

footer
```

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation
- style: Formatting
- refactor: Code restructuring
- test: Adding tests
- chore: Maintenance

## Troubleshooting

### Common Issues

1. **Build Errors**
   - Check Node.js version
   - Clear npm cache
   - Delete node_modules and reinstall

2. **Runtime Errors**
   - Check browser console
   - Verify API endpoints
   - Check environment variables

3. **Type Errors**
   - Run `npm run typecheck`
   - Update @types packages
   - Check tsconfig.json settings

## License

This project is proprietary and confidential.

## Support

For support, please contact the development team or create an issue in the repository.

## Acknowledgments

- React Team
- Redux Team
- Emotion Team
- Framer Motion Team
- Vite Team
