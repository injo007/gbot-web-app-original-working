import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import styled from '@emotion/styled';
import { motion } from 'framer-motion';
import { Card } from '../../components/Card/Card';
import { Input } from '../../components/Input/Input';
import { Button } from '../../components/Button/Button';
import { useRequestEmergencyAccessMutation } from '../../store/apis/whitelistApi';

const EmergencyContainer = styled.div`
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: ${({ theme }) => theme.spacing[4]};
  background: ${({ theme }) => theme.current.warning.emphasis}10;
`;

const EmergencyCard = styled(Card)`
  width: 100%;
  max-width: 500px;
`;

const WarningIcon = styled(motion.div)`
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: ${({ theme }) => theme.spacing[6]};
  color: ${({ theme }) => theme.current.warning.emphasis};

  svg {
    width: 48px;
    height: 48px;
  }
`;

const Title = styled.h1`
  text-align: center;
  color: ${({ theme }) => theme.current.warning.emphasis};
  font-size: ${({ theme }) => theme.fontSizes['2xl']};
  margin-bottom: ${({ theme }) => theme.spacing[4]};
`;

const Description = styled.p`
  text-align: center;
  color: ${({ theme }) => theme.current.fg.muted};
  margin-bottom: ${({ theme }) => theme.spacing[6]};
`;

const Form = styled.form`
  display: flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.spacing[4]};
`;

const InfoBox = styled.div`
  background: ${({ theme }) => theme.current.canvas.subtle};
  border: 1px solid ${({ theme }) => theme.current.border.subtle};
  border-radius: ${({ theme }) => theme.radii.md};
  padding: ${({ theme }) => theme.spacing[4]};
  margin-bottom: ${({ theme }) => theme.spacing[4]};
`;

const ErrorMessage = styled(motion.div)`
  color: ${({ theme }) => theme.current.danger.emphasis};
  font-size: ${({ theme }) => theme.fontSizes.sm};
  text-align: center;
  padding: ${({ theme }) => theme.spacing[2]};
  background: ${({ theme }) => `${theme.current.danger.emphasis}10`};
  border-radius: ${({ theme }) => theme.radii.md};
  margin-top: ${({ theme }) => theme.spacing[4]};
`;

const EmergencyAccessPage: React.FC = () => {
  const navigate = useNavigate();
  const [requestAccess, { isLoading }] = useRequestEmergencyAccessMutation();
  const [error, setError] = useState<string | null>(null);
  const [currentIP, setCurrentIP] = useState<string>('');

  useEffect(() => {
    // Detect current IP
    fetch('https://api.ipify.org?format=json')
      .then((res) => res.json())
      .then((data) => setCurrentIP(data.ip))
      .catch(() => setCurrentIP('Unable to detect IP'));
  }, []);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);

    const formData = new FormData(e.currentTarget);
    const ip = formData.get('ip') as string;
    const token = formData.get('token') as string;

    try {
      const result = await requestAccess({ ip, token }).unwrap();
      if (result.success) {
        navigate('/dashboard');
      } else {
        setError(result.message || 'Emergency access request failed');
      }
    } catch (err) {
      setError('An error occurred while requesting emergency access');
    }
  };

  return (
    <EmergencyContainer>
      <EmergencyCard variant="elevated">
        <WarningIcon
          initial={{ scale: 0.5, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.3 }}
        >
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2L1 21h22L12 2zm0 3.45l8.27 14.3H3.73L12 5.45zm1 12.55v2h-2v-2h2zm0-7v5h-2v-5h2z"/>
          </svg>
        </WarningIcon>

        <Title>Emergency Access</Title>
        <Description>
          Use this form to request emergency access if you're locked out due to IP
          restrictions. You'll need your emergency access token.
        </Description>

        <InfoBox>
          <strong>Your Current IP:</strong> {currentIP}
        </InfoBox>

        <Form onSubmit={handleSubmit}>
          <Input
            name="ip"
            label="IP Address"
            placeholder="Enter IP address to whitelist"
            defaultValue={currentIP}
            required
          />
          <Input
            name="token"
            label="Emergency Access Token"
            placeholder="Enter your emergency access token"
            required
          />
          <Button
            type="submit"
            variant="primary"
            fullWidth
            isLoading={isLoading}
          >
            Request Emergency Access
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
            onClick={() => navigate('/login')}
          >
            Back to Login
          </Button>
        </div>
      </EmergencyCard>
    </EmergencyContainer>
  );
};

export default EmergencyAccessPage;
