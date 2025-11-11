import React, { useState } from 'react';
import styled from '@emotion/styled';
import { Card } from '../components/Card/Card';
import { Button } from '../components/Button/Button';
import { DataTable } from '../components/DataTable/DataTable';
import { Modal } from '../components/Modal/Modal';
import { Input } from '../components/Input/Input';
import {
  useListDomainsQuery,
  useChangeDomainStatusMutation,
  useMarkUsedDomainsMutation,
  useBulkDomainChangeMutation,
} from '../store/apis/domainsApi';
import { withAuth } from '../components/auth/AuthGuard';
import type { Domain } from '../store/types';

const PageHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: ${({ theme }) => theme.spacing[6]};
`;

const ActionBar = styled.div`
  display: flex;
  gap: ${({ theme }) => theme.spacing[3]};
`;

const Form = styled.form`
  display: flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.spacing[4]};
`;

const StatusBadge = styled.span<{ status: string }>`
  padding: 4px 8px;
  border-radius: 4px;
  font-size: ${({ theme }) => theme.fontSizes.sm};
  background: ${({ status, theme }) =>
    status === 'available'
      ? `${theme.current.success.emphasis}20`
      : status === 'in_use'
      ? `${theme.current.warning.emphasis}20`
      : `${theme.current.danger.emphasis}20`};
  color: ${({ status, theme }) =>
    status === 'available'
      ? theme.current.success.emphasis
      : status === 'in_use'
      ? theme.current.warning.emphasis
      : theme.current.danger.emphasis};
`;

const DomainsPage: React.FC = () => {
  const { data: domains, isLoading } = useListDomainsQuery();
  const [changeDomainStatus] = useChangeDomainStatusMutation();
  const [markUsedDomains] = useMarkUsedDomainsMutation();
  const [bulkDomainChange] = useBulkDomainChangeMutation();

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isBulkModalOpen, setIsBulkModalOpen] = useState(false);
  const [selectedDomain, setSelectedDomain] = useState<Domain | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleStatusChange = async (domain: Domain, newStatus: string) => {
    try {
      await changeDomainStatus({
        subdomain: domain.domain_name,
        status: newStatus as 'available' | 'in_use' | 'used',
      }).unwrap();
    } catch (err) {
      setError('Failed to update domain status');
    }
  };

  const handleBulkChange = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);

    const formData = new FormData(e.currentTarget);
    const accounts = (formData.get('accounts') as string)
      .split('\n')
      .map((a) => a.trim())
      .filter(Boolean);
    const prefix = formData.get('prefix') as string;

    try {
      await bulkDomainChange({ accounts, subdomain_prefix: prefix }).unwrap();
      setIsBulkModalOpen(false);
    } catch (err) {
      setError('Failed to perform bulk domain change');
    }
  };

  const handleMarkUsed = async () => {
    try {
      await markUsedDomains().unwrap();
    } catch (err) {
      setError('Failed to mark used domains');
    }
  };

  const columns = [
    {
      key: 'domain_name',
      title: 'Domain',
      width: '40%',
    },
    {
      key: 'status',
      title: 'Status',
      width: '20%',
      render: (value: string) => <StatusBadge status={value}>{value}</StatusBadge>,
    },
    {
      key: 'user_count',
      title: 'Users',
      width: '15%',
    },
    {
      key: 'actions',
      title: 'Actions',
      width: '25%',
      render: (_: any, domain: Domain) => (
        <div style={{ display: 'flex', gap: '8px' }}>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              setSelectedDomain(domain);
              setIsModalOpen(true);
            }}
          >
            Change Status
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader>
        <h1>Domain Management</h1>
        <ActionBar>
          <Button variant="secondary" onClick={handleMarkUsed}>
            Mark Used Domains
          </Button>
          <Button
            variant="primary"
            onClick={() => setIsBulkModalOpen(true)}
          >
            Bulk Domain Change
          </Button>
        </ActionBar>
      </PageHeader>

      <Card>
        <DataTable
          columns={columns}
          data={domains?.data || []}
          isLoading={isLoading}
          emptyMessage="No domains found"
          rowKey="domain_name"
        />
      </Card>

      {/* Status Change Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setSelectedDomain(null);
          setError(null);
        }}
        title="Change Domain Status"
      >
        <Form>
          <Input
            name="domain"
            label="Domain"
            value={selectedDomain?.domain_name}
            disabled
          />
          <Input
            name="status"
            label="Status"
            type="select"
            defaultValue={selectedDomain?.status || 'available'}
            onChange={(e) => {
              if (selectedDomain) {
                handleStatusChange(selectedDomain, e.target.value);
              }
            }}
          >
            <option value="available">Available</option>
            <option value="in_use">In Use</option>
            <option value="used">Used</option>
          </Input>

          {error && (
            <div style={{ color: '#da3633', marginTop: '8px' }}>{error}</div>
          )}
        </Form>
      </Modal>

      {/* Bulk Change Modal */}
      <Modal
        isOpen={isBulkModalOpen}
        onClose={() => {
          setIsBulkModalOpen(false);
          setError(null);
        }}
        title="Bulk Domain Change"
      >
        <Form onSubmit={handleBulkChange}>
          <Input
            name="accounts"
            label="Account List"
            type="textarea"
            placeholder="Enter one account per line"
            required
          />
          <Input
            name="prefix"
            label="Subdomain Prefix (Optional)"
            placeholder="Leave empty for random prefix"
          />

          {error && (
            <div style={{ color: '#da3633', marginTop: '8px' }}>{error}</div>
          )}

          <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
            <Button type="submit" variant="primary">
              Start Bulk Change
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setIsBulkModalOpen(false);
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

export default withAuth(DomainsPage);
