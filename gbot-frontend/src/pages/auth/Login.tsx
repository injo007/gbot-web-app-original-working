import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import styled from '@emotion/styled';
import { motion } from 'framer-motion';
import { Card } from '../../components/Card/Card';
import { Input } from '../../components/Input/Input';
import { Button } from '../../components/Button/Button';
import { useLoginMutation } from '../../store/apis/authApi';

const LoginContainer = styled.div`
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: ${({ theme }) => theme.spacing[4]};
  background: ${({ theme }) => theme.current.canvas.subtle};
`;

const LoginCard = styled(Card)`
  width: 100%;
  max-width: 400px;
`;

const Logo = styled(motion.div)`
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: ${({ theme }) => theme.spacing[6]};
  color: ${({ theme }) => theme.current.accent.emphasis};

  svg {
    width: 48px;
    height: 48px;
  }
`;

const Form = styled.form`
  display: flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.spacing[4]};
`;

const ErrorMessage = styled(motion.div)`
  color: ${({ theme }) => theme.current.danger.emphasis};
  font-size: ${({ theme }) => theme.fontSizes.sm};
  text-align: center;
  padding: ${({ theme }) => theme.spacing[2]};
  background: ${({ theme }) => `${theme.current.danger.emphasis}10`};
  border-radius: ${({ theme }) => theme.radii.md};
`;

const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const [login, { isLoading }] = useLoginMutation();
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);

    const formData = new FormData(e.currentTarget);
    const username = formData.get('username') as string;
    const password = formData.get('password') as string;

    try {
      const result = await login({ username, password }).unwrap();
      if (result.success) {
        navigate('/dashboard');
      } else {
        setError(result.error || 'Login failed');
      }
    } catch (err) {
      setError('An error occurred during login');
    }
  };

  return (
    <LoginContainer>
      <LoginCard>
        <Logo
          initial={{ scale: 0.5, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.3 }}
        >
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2a10 10 0 1010 10A10 10 0 0012 2zm0 18a8 8 0 118-8 8 8 0 01-8 8zm4-9h-3V8a1 1 0 00-2 0v3H8a1 1 0 000 2h3v3a1 1 0 002 0v-3h3a1 1 0 000-2z"/>
          </svg>
        </Logo>

        <Form onSubmit={handleSubmit}>
          <Input
            name="username"
            label="Username"
            placeholder="Enter your username"
            autoComplete="username"
            required
          />
          <Input
            name="password"
            type="password"
            label="Password"
            placeholder="Enter your password"
            autoComplete="current-password"
            required
          />
          <Button
            type="submit"
            variant="primary"
            fullWidth
            isLoading={isLoading}
          >
            Sign In
          </Button>
        </Form>

        {error && (
          <ErrorMessage
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
          >
            {error}
          </ErrorMessage>
        )}

        <div style={{ marginTop: '24px', textAlign: 'center' }}>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate('/emergency-access')}
          >
            Emergency Access
          </Button>
        </div>
      </LoginCard>
    </LoginContainer>
  );
};

export default LoginPage;
