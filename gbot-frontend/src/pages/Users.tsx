import React, { useState } from 'react';
import styled from '@emotion/styled';
import { Card } from '../components/Card/Card';
import { Button } from '../components/Button/Button';
import { DataTable } from '../components/DataTable/DataTable';
import { Modal } from '../components/Modal/Modal';
import { Input } from '../components/Input/Input';
import {
  useListUsersQuery,
  useAddUserMutation,
  useEditUserMutation,
  useDeleteUserMutation,
} from '../store/apis/usersApi';
import { withAuth } from '../components/auth/AuthGuard';
import type { User } from '../store/types';

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

interface UserFormData {
  username: string;
  password: string;
  role: 'admin' | 'support' | 'mailer';
}

const UsersPage: React.FC = () => {
  const { data: users, isLoading } = useListUsersQuery();
  const [addUser] = useAddUserMutation();
  const [editUser] = useEditUserMutation();
  const [deleteUser] = useDeleteUserMutation();

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);

    const formData = new FormData(e.currentTarget);
    const userData: UserFormData = {
      username: formData.get('username') as string,
      password: formData.get('password') as string,
      role: formData.get('role') as UserFormData['role'],
    };

    try {
      if (editingUser) {
        await editUser({ ...userData, username: editingUser.username }).unwrap();
      } else {
        await addUser(userData).unwrap();
      }
      setIsModalOpen(false);
      setEditingUser(null);
    } catch (err) {
      setError('Failed to save user');
    }
  };

  const handleDelete = async (username: string) => {
    if (window.confirm('Are you sure you want to delete this user?')) {
      try {
        await deleteUser(username).unwrap();
      } catch (err) {
        setError('Failed to delete user');
      }
    }
  };

  const columns = [
    {
      key: 'username',
      title: 'Username',
      width: '30%',
    },
    {
      key: 'role',
      title: 'Role',
      width: '20%',
      render: (value: string) => (
        <span
          style={{
            padding: '4px 8px',
            borderRadius: '4px',
            backgroundColor:
              value === 'admin'
                ? '#da363320'
                : value === 'mailer'
                ? '#fb850020'
                : '#2da44e20',
            color:
              value === 'admin'
                ? '#da3633'
                : value === 'mailer'
                ? '#fb8500'
                : '#2da44e',
          }}
        >
          {value}
        </span>
      ),
    },
    {
      key: 'actions',
      title: 'Actions',
      width: '20%',
      render: (_: any, row: User) => (
        <div style={{ display: 'flex', gap: '8px' }}>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              setEditingUser(row);
              setIsModalOpen(true);
            }}
          >
            Edit
          </Button>
          <Button
            size="sm"
            variant="danger"
            onClick={() => handleDelete(row.username)}
          >
            Delete
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader>
        <h1>User Management</h1>
        <Button
          variant="primary"
          onClick={() => {
            setEditingUser(null);
            setIsModalOpen(true);
          }}
        >
          Add User
        </Button>
      </PageHeader>

      <Card>
        <DataTable
          columns={columns}
          data={users?.data || []}
          isLoading={isLoading}
          emptyMessage="No users found"
          rowKey="username"
        />
      </Card>

      <Modal
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setEditingUser(null);
          setError(null);
        }}
        title={editingUser ? 'Edit User' : 'Add User'}
      >
        <Form onSubmit={handleSubmit}>
          <Input
            name="username"
            label="Username"
            defaultValue={editingUser?.username}
            disabled={!!editingUser}
            required
          />
          <Input
            name="password"
            type="password"
            label={editingUser ? 'New Password (optional)' : 'Password'}
            required={!editingUser}
          />
          <Input
            name="role"
            label="Role"
            type="select"
            defaultValue={editingUser?.role || 'support'}
            required
          >
            <option value="support">Support</option>
            <option value="mailer">Mailer</option>
            <option value="admin">Admin</option>
          </Input>

          {error && (
            <div style={{ color: '#da3633', marginTop: '8px' }}>{error}</div>
          )}

          <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
            <Button type="submit" variant="primary">
              {editingUser ? 'Save Changes' : 'Add User'}
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setIsModalOpen(false);
                setEditingUser(null);
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

export default withAuth(UsersPage, true);
