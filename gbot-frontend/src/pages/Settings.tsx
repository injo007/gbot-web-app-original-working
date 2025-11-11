import React, { useState } from 'react';
import styled from '@emotion/styled';
import { Card } from '../components/Card/Card';
import { Button } from '../components/Button/Button';
import { Input } from '../components/Input/Input';
import {
  useGetSettingsQuery,
  useUpdateSettingsMutation,
  useRunBackupMutation,
  useCheckSystemHealthQuery,
} from '../store/apis/settingsApi';
import { withAuth } from '../components/auth/AuthGuard';

const PageHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: ${({ theme }) => theme.spacing[6]};
`;

const SettingsGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: ${({ theme }) => theme.spacing[6]};
`;

const Form = styled.form`
  display: flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.spacing[4]};
`;

const StatusIndicator = styled.div<{ status: 'healthy' | 'warning' | 'error' }>`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing[2]};
  padding: ${({ theme }) => theme.spacing[2]};
  border-radius: ${({ theme }) => theme.radii.md};
  background: ${({ status, theme }) =>
    status === 'healthy'
      ? `${theme.current.success.emphasis}20`
      : status === 'warning'
      ? `${theme.current.warning.emphasis}20`
      : `${theme.current.danger.emphasis}20`};
  color: ${({ status, theme }) =>
    status === 'healthy'
      ? theme.current.success.emphasis
      : status === 'warning'
      ? theme.current.warning.emphasis
      : theme.current.danger.emphasis};

  &::before {
    content: '';
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: currentColor;
  }
`;

const SettingsPage: React.FC = () => {
  const { data: settings, isLoading } = useGetSettingsQuery();
  const [updateSettings] = useUpdateSettingsMutation();
  const [runBackup] = useRunBackupMutation();
  const { data: healthStatus, refetch: refetchHealth } = useCheckSystemHealthQuery();

  const [error, setError] = useState<string | null>(null);
  const [backupInProgress, setBackupInProgress] = useState(false);

  const handleSettingsSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);

    const formData = new FormData(e.currentTarget);
    const updatedSettings = {
      backup_frequency: Number(formData.get('backup_frequency')),
      max_users_per_domain: Number(formData.get('max_users_per_domain')),
      domain_cooldown_hours: Number(formData.get('domain_cooldown_hours')),
      emergency_token: formData.get('emergency_token') as string,
    };

    try {
      await updateSettings(updatedSettings).unwrap();
    } catch (err) {
      setError('Failed to update settings');
    }
  };

  const handleBackup = async () => {
    try {
      setBackupInProgress(true);
      await runBackup().unwrap();
    } catch (err) {
      setError('Failed to initiate backup');
    } finally {
      setBackupInProgress(false);
    }
  };

  if (isLoading) {
    return <div>Loading settings...</div>;
  }

  return (
    <div>
      <PageHeader>
        <h1>System Settings</h1>
        <Button
          variant="secondary"
          onClick={() => refetchHealth()}
        >
          Refresh Status
        </Button>
      </PageHeader>

      <SettingsGrid>
        <Card>
          <h2>System Health</h2>
          <div style={{ marginTop: '16px' }}>
            {healthStatus?.checks.map((check) => (
              <div
                key={check.name}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginBottom: '8px',
                }}
              >
                <span>{check.name}</span>
                <StatusIndicator status={check.status}>
                  {check.status}
                </StatusIndicator>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <h2>Backup & Maintenance</h2>
          <div style={{ marginTop: '16px' }}>
            <Button
              variant="primary"
              fullWidth
              isLoading={backupInProgress}
              onClick={handleBackup}
            >
              Run Manual Backup
            </Button>
            {settings?.last_backup_at && (
              <div style={{ marginTop: '8px', fontSize: '14px', color: '#666' }}>
                Last backup: {new Date(settings.last_backup_at).toLocaleString()}
              </div>
            )}
          </div>
        </Card>
      </SettingsGrid>

      <Card style={{ marginTop: '24px' }}>
        <h2>Configuration</h2>
        <Form onSubmit={handleSettingsSubmit}>
          <Input
            name="backup_frequency"
            label="Backup Frequency (hours)"
            type="number"
            defaultValue={settings?.backup_frequency}
            required
          />
          <Input
            name="max_users_per_domain"
            label="Max Users per Domain"
            type="number"
            defaultValue={settings?.max_users_per_domain}
            required
          />
          <Input
            name="domain_cooldown_hours"
            label="Domain Cooldown Period (hours)"
            type="number"
            defaultValue={settings?.domain_cooldown_hours}
            required
          />
          <Input
            name="emergency_token"
            label="Emergency Access Token"
            type="password"
            defaultValue={settings?.emergency_token}
            required
          />

          {error && (
            <div style={{ color: '#da3633', marginTop: '8px' }}>{error}</div>
          )}

          <Button type="submit" variant="primary">
            Save Settings
          </Button>
        </Form>
      </Card>
    </div>
  );
};

export default withAuth(SettingsPage, true);
