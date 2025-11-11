import React, { useState } from 'react';
import styled from '@emotion/styled';
import { Card } from '../components/Card/Card';
import { Button } from '../components/Button/Button';
import { DataTable } from '../components/DataTable/DataTable';
import { Modal } from '../components/Modal/Modal';
import { Input } from '../components/Input/Input';
import {
  useListWhitelistedIPsQuery,
  useAddToWhitelistMutation,
  useDeleteFromWhitelistMutation,
  useLazyCheckIPWhitelistedQuery,
} from '../store/apis/whitelistApi';
import { withAuth } from '../components/auth/AuthGuard';
import type { WhitelistedIP } from '../store/types';

const PageHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: ${({ theme }) => theme.spacing[6]};
`;

const Form = styled.form`
  display: flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.spacing[4]};
`;

const IPStatus = styled.div<{ isWhitelisted: boolean }>`
  padding: 8px 12px;
  border-radius: ${({ theme }) => theme.radii.md};
  background: ${({ isWhitelisted, theme }) =>
    isWhitelisted
      ? `${theme.current.success.emphasis}20`
      : `${theme.current.danger.emphasis}20`};
  color: ${({ isWhitelisted, theme }) =>
    isWhitelisted
      ? theme.current.success.emphasis
      : theme.current.danger.emphasis};
  margin-top: ${({ theme }) => theme.spacing[4]};
  text-align: center;
`;

const WhitelistPage: React.FC = () => {
  const { data: ips, isLoading } = useListWhitelistedIPsQuery();
  const [addToWhitelist] = useAddToWhitelistMutation();
  const [deleteFromWhitelist] = useDeleteFromWhitelistMutation();
  const [triggerCheckIP, { data: ipStatus }] = useLazyCheckIPWhitelistedQuery();

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [checkedIP, setCheckedIP] = useState<string>('');

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);

    const formData = new FormData(e.currentTarget);
    const ip = formData.get('ip') as string;

    try {
      await addToWhitelist(ip).unwrap();
      setIsModalOpen(false);
    } catch (err) {
      setError('Failed to add IP to whitelist');
    }
  };

  const handleRemove = async (ip: string) => {
    if (window.confirm('Are you sure you want to remove this IP from the whitelist?')) {
      try {
        await deleteFromWhitelist(ip).unwrap();
      } catch (err) {
        setError('Failed to remove IP from whitelist');
      }
    }
  };

  const handleCheckIP = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const ip = formData.get('check_ip') as string;
    setCheckedIP(ip);
    await triggerCheckIP(ip);
  };

  const columns = [
    {
      key: 'ip_address',
      title: 'IP Address',
      width: '50%',
    },
    {
      key: 'added_date',
      title: 'Added',
      width: '25%',
      render: (value: string) => new Date(value).toLocaleDateString(),
    },
    {
      key: 'actions',
      title: 'Actions',
      width: '25%',
      render: (_: any, row: WhitelistedIP) => (
        <Button
          size="sm"
          variant="danger"
          onClick={() => handleRemove(row.ip_address)}
        >
          Remove
        </Button>
      ),
    },
  ];

  return (
    <div>
      <PageHeader>
        <h1>IP Whitelist</h1>
        <Button
          variant="primary"
          onClick={() => setIsModalOpen(true)}
        >
          Add IP
        </Button>
      </PageHeader>

      <Card style={{ marginBottom: '24px' }}>
        <h3>Check IP Status</h3>
        <Form onSubmit={handleCheckIP}>
          <div style={{ display: 'flex', gap: '8px' }}>
            <div style={{ flex: 1 }}>
              <Input
                name="check_ip"
                placeholder="Enter IP address to check"
                required
              />
            </div>
            <Button type="submit" variant="secondary">
              Check
            </Button>
          </div>
        </Form>
        {ipStatus && checkedIP && (
          <IPStatus isWhitelisted={!!(ipStatus as any).data?.whitelisted}>
            {checkedIP} is {(ipStatus as any).data?.whitelisted ? 'whitelisted' : 'not whitelisted'}
          </IPStatus>
        )}
      </Card>

      <Card>
        <DataTable
          columns={columns}
          data={ips?.data || []}
          isLoading={isLoading}
          emptyMessage="No whitelisted IPs found"
          rowKey="ip_address"
        />
      </Card>

      <Modal
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setError(null);
        }}
        title="Add IP to Whitelist"
      >
        <Form onSubmit={handleSubmit}>
          <Input
            name="ip"
            label="IP Address"
            placeholder="Enter IP address"
            required
          />
          <Input
            name="description"
            label="Description"
            placeholder="Enter a description for this IP"
            required
          />

          {error && (
            <div style={{ color: '#da3633', marginTop: '8px' }}>{error}</div>
          )}

          <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
            <Button type="submit" variant="primary">
              Add IP
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setIsModalOpen(false);
                setError(null);
              }}
            >
              Cancel
            </Button>
          </div>
        </Form>
      </Modal>
    </div>
  );
};

export default withAuth(WhitelistPage, true);
