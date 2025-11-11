import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Provider } from 'react-redux';
import { ThemeProvider } from './theme/ThemeProvider';
import { store } from './store';
import { AppLayout } from './layouts/AppLayout';
import LoginPage from './pages/auth/Login';
import EmergencyAccessPage from './pages/auth/EmergencyAccess';
import DashboardPage from './pages/Dashboard';
import UsersPage from './pages/Users';
import DomainsPage from './pages/Domains';
import WhitelistPage from './pages/Whitelist';
import SettingsPage from './pages/Settings';

// Routes that use the app layout (with sidebar and header)
const appRoutes = [
  {
    path: '/dashboard',
    element: <DashboardPage />,
  },
  {
    path: '/users',
    element: <UsersPage />,
  },
  {
    path: '/domains',
    element: <DomainsPage />,
  },
  {
    path: '/whitelist',
    element: <WhitelistPage />,
  },
  {
    path: '/settings',
    element: <SettingsPage />,
  },
];

// Auth routes (without app layout)
const authRoutes = [
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/emergency-access',
    element: <EmergencyAccessPage />,
  },
];

const App: React.FC = () => {
  return (
    <Provider store={store}>
      <ThemeProvider>
        <BrowserRouter>
          <Routes>
            {/* Redirect root to dashboard */}
            <Route
              path="/"
              element={<Navigate to="/dashboard" replace />}
            />

            {/* Auth routes */}
            {authRoutes.map(({ path, element }) => (
              <Route
                key={path}
                path={path}
                element={element}
              />
            ))}

            {/* App routes with layout */}
            <Route element={<AppLayout />}>
              {appRoutes.map(({ path, element }) => (
                <Route
                  key={path}
                  path={path}
                  element={element}
                />
              ))}
            </Route>

            {/* 404 route */}
            <Route
              path="*"
              element={
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: '100vh',
                  flexDirection: 'column',
                  gap: '16px',
                }}>
                  <h1>404 - Page Not Found</h1>
                  <p>The page you're looking for doesn't exist.</p>
                  <a href="/dashboard" style={{ color: '#0969da' }}>
                    Return to Dashboard
                  </a>
                </div>
              }
            />
          </Routes>
        </BrowserRouter>
      </ThemeProvider>
    </Provider>
  );
};

export default App;
