import React from 'react';
import styled from '@emotion/styled';
import { motion } from 'framer-motion';
import { Card } from '../components/Card/Card';
import { Button } from '../components/Button/Button';
import { useGetDomainStatsQuery } from '../store/apis/domainsApi';
import { useListWhitelistedIPsQuery } from '../store/apis/whitelistApi';
import { useListUsersQuery } from '../store/apis/usersApi';
import { withAuth } from '../components/auth/AuthGuard';

const DashboardGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: ${({ theme }) => theme.spacing[6]};
  margin-bottom: ${({ theme }) => theme.spacing[6]};
`;

const StatCard = styled(Card)`
  text-align: center;
  padding: ${({ theme }) => theme.spacing[6]};
`;

const StatValue = styled.div`
  font-size: ${({ theme }) => theme.fontSizes['4xl']};
  font-weight: ${({ theme }) => theme.fontWeights.bold};
  color: ${({ theme }) => theme.current.accent.emphasis};
  margin-bottom: ${({ theme }) => theme.spacing[2]};
`;

const StatLabel = styled.div`
  font-size: ${({ theme }) => theme.fontSizes.sm};
  color: ${({ theme }) => theme.current.fg.muted};
`;

const QuickActions = styled(Card)`
  margin-bottom: ${({ theme }) => theme.spacing[6]};
`;

const ActionGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: ${({ theme }) => theme.spacing[4]};
  padding: ${({ theme }) => theme.spacing[4]};
`;

const RecentActivity = styled(Card)`
  margin-bottom: ${({ theme }) => theme.spacing[6]};
`;

const ActivityList = styled.div`
  display: flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.spacing[2]};
`;

const ActivityItem = styled.div`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing[3]};
  padding: ${({ theme }) => theme.spacing[3]};
  border-radius: ${({ theme }) => theme.radii.md};
  background: ${({ theme }) => theme.current.canvas.subtle};

  &:hover {
    background: ${({ theme }) => theme.current.canvas.inset};
  }
`;

const Dashboard: React.FC = () => {
  const { data: domainStats, isLoading: isLoadingDomains } = useGetDomainStatsQuery();
  const { data: whitelistData, isLoading: isLoadingWhitelist } = useListWhitelistedIPsQuery();
  const { data: usersData, isLoading: isLoadingUsers } = useListUsersQuery();

  const stats = [
    {
      label: 'Total Domains',
      value: domainStats?.data?.total_domains || 0,
      loading: isLoadingDomains,
    },
    {
      label: 'Active Users',
      value: usersData?.data?.length || 0,
      loading: isLoadingUsers,
    },
    {
      label: 'Whitelisted IPs',
      value: whitelistData?.data?.length || 0,
      loading: isLoadingWhitelist,
    },
  ];

  const quickActions = [
    { label: 'Add User', icon: '👤', path: '/users/new' },
    { label: 'Add Domain', icon: '🌐', path: '/domains/new' },
    { label: 'Whitelist IP', icon: '🛡️', path: '/whitelist/new' },
    { label: 'System Settings', icon: '⚙️', path: '/settings' },
  ];

  return (
    <div>
      <DashboardGrid>
        {stats.map((stat) => (
          <StatCard key={stat.label}>
            <StatValue>
              {stat.loading ? (
                <motion.div
                  animate={{ opacity: [0.5, 1, 0.5] }}
                  transition={{ duration: 1.5, repeat: Infinity }}
                >
                  ...
                </motion.div>
              ) : (
                stat.value
              )}
            </StatValue>
            <StatLabel>{stat.label}</StatLabel>
          </StatCard>
        ))}
      </DashboardGrid>

      <QuickActions>
        <h2>Quick Actions</h2>
        <ActionGrid>
          {quickActions.map((action) => (
            <Button
              key={action.label}
              variant="secondary"
              fullWidth
              onClick={() => {
                // Navigate to the action path
                window.location.href = action.path;
              }}
            >
              <span style={{ marginRight: '8px' }}>{action.icon}</span>
              {action.label}
            </Button>
          ))}
        </ActionGrid>
      </QuickActions>

      <RecentActivity>
        <h2>Recent Activity</h2>
        <ActivityList>
          {/* Placeholder for recent activity - to be implemented */}
          <ActivityItem>
            <span>🔄</span>
            <div>
              <strong>System Update</strong>
              <p>Latest backup completed successfully</p>
            </div>
            <span style={{ marginLeft: 'auto', color: '#666' }}>2m ago</span>
          </ActivityItem>
          <ActivityItem>
            <span>👤</span>
            <div>
              <strong>User Management</strong>
              <p>New user account created</p>
            </div>
            <span style={{ marginLeft: 'auto', color: '#666' }}>15m ago</span>
          </ActivityItem>
          <ActivityItem>
            <span>🌐</span>
            <div>
              <strong>Domain Update</strong>
              <p>3 new domains added to the system</p>
            </div>
            <span style={{ marginLeft: 'auto', color: '#666' }}>1h ago</span>
          </ActivityItem>
        </ActivityList>
      </RecentActivity>
    </div>
  );
};

export default withAuth(Dashboard);
