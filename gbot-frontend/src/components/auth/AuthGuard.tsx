import React, { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useSelector } from 'react-redux';
import { selectAuth } from '../../store/slices/authSlice';
import { useCheckAuthQuery } from '../../store/apis/authApi';

interface AuthGuardProps {
  children: React.ReactNode;
  requireAdmin?: boolean;
}

export const AuthGuard: React.FC<AuthGuardProps> = ({ children, requireAdmin = false }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated, user, isLoading } = useSelector(selectAuth);
  const { refetch } = useCheckAuthQuery();

  useEffect(() => {
    const checkAuth = async () => {
      if (!isAuthenticated && !isLoading) {
        try {
          await refetch();
        } catch (error) {
          // If auth check fails, redirect to login
          navigate('/login', {
            state: { from: location.pathname },
            replace: true,
          });
        }
      }
    };

    checkAuth();
  }, [isAuthenticated, isLoading, refetch, navigate, location]);

  // Show nothing while checking authentication
  if (isLoading) {
    return null;
  }

  // If not authenticated, don't render children
  if (!isAuthenticated) {
    return null;
  }

  // If admin access is required but user is not admin
  if (requireAdmin && user?.role !== 'admin') {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100vh',
          padding: '20px',
          textAlign: 'center',
          color: '#cf222e',
        }}
      >
        <div>
          <h1>Access Denied</h1>
          <p>You need administrator privileges to access this page.</p>
        </div>
      </div>
    );
  }

  // If all checks pass, render children
  return <>{children}</>;
};

export const withAuth = (
  WrappedComponent: React.ComponentType<any>,
  requireAdmin = false
) => {
  return function WithAuthComponent(props: any) {
    return (
      <AuthGuard requireAdmin={requireAdmin}>
        <WrappedComponent {...props} />
      </AuthGuard>
    );
  };
};

export default AuthGuard;
