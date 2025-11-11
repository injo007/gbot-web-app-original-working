import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useSelector } from 'react-redux';
import styled from '@emotion/styled';
import { motion, AnimatePresence } from 'framer-motion';
import { selectUser } from '../store/slices/authSlice';
import { useLogoutMutation } from '../store/apis/authApi';
import { Button } from '../components/Button/Button';

interface AppLayoutProps {
  children: React.ReactNode;
}

const LayoutContainer = styled.div`
  display: flex;
  min-height: 100vh;
  background: ${({ theme }) => theme.current.canvas.subtle};
`;

const Sidebar = styled(motion.aside)<{ isOpen: boolean }>`
  width: ${({ isOpen }) => (isOpen ? '280px' : '80px')};
  background: ${({ theme }) => theme.current.canvas.default};
  border-right: 1px solid ${({ theme }) => theme.current.border.default};
  display: flex;
  flex-direction: column;
  transition: width ${({ theme }) => theme.transitions.default};
  position: fixed;
  top: 0;
  bottom: 0;
  z-index: ${({ theme }) => theme.zIndices.sidebar};
`;

const MainContent = styled.main<{ sidebarOpen: boolean }>`
  flex: 1;
  margin-left: ${({ sidebarOpen }) => (sidebarOpen ? '280px' : '80px')};
  padding: ${({ theme }) => theme.spacing[6]};
  transition: margin-left ${({ theme }) => theme.transitions.default};
`;

const Header = styled.header`
  height: 64px;
  background: ${({ theme }) => theme.current.canvas.default};
  border-bottom: 1px solid ${({ theme }) => theme.current.border.default};
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: ${({ theme }) => `0 ${theme.spacing[4]}`};
  position: sticky;
  top: 0;
  z-index: ${({ theme }) => theme.zIndices.header};
`;

const Logo = styled.div`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing[3]};
  padding: ${({ theme }) => theme.spacing[4]};
  color: ${({ theme }) => theme.current.accent.emphasis};
  font-size: ${({ theme }) => theme.fontSizes.lg};
  font-weight: ${({ theme }) => theme.fontWeights.bold};
`;

const NavItem = styled(motion.a)<{ active?: boolean }>`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing[3]};
  padding: ${({ theme }) => theme.spacing[3]};
  color: ${({ theme, active }) =>
    active ? theme.current.accent.emphasis : theme.current.fg.default};
  text-decoration: none;
  cursor: pointer;
  transition: all ${({ theme }) => theme.transitions.default};

  &:hover {
    background: ${({ theme }) => theme.current.canvas.subtle};
  }

  svg {
    width: 20px;
    height: 20px;
  }
`;

const UserInfo = styled.div`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing[4]};
`;

const UserName = styled.div`
  display: flex;
  flex-direction: column;
  
  span:first-of-type {
    font-weight: ${({ theme }) => theme.fontWeights.medium};
    color: ${({ theme }) => theme.current.fg.default};
  }
  
  span:last-of-type {
    font-size: ${({ theme }) => theme.fontSizes.sm};
    color: ${({ theme }) => theme.current.fg.muted};
  }
`;

export const AppLayout: React.FC<AppLayoutProps> = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const user = useSelector(selectUser);
  const [logout] = useLogoutMutation();
  const [isSidebarOpen, setIsSidebarOpen] = React.useState(true);

  const handleLogout = async () => {
    try {
      await logout().unwrap();
      navigate('/login');
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  const navItems = [
    { path: '/dashboard', label: 'Dashboard', icon: '📊' },
    { path: '/users', label: 'Users', icon: '👥', adminOnly: true },
    { path: '/domains', label: 'Domains', icon: '🌐' },
    { path: '/whitelist', label: 'IP Whitelist', icon: '🛡️', adminOnly: true },
    { path: '/settings', label: 'Settings', icon: '⚙️', adminOnly: true },
  ];

  return (
    <LayoutContainer>
      <Sidebar
        isOpen={isSidebarOpen}
        initial={false}
        animate={{ width: isSidebarOpen ? 280 : 80 }}
      >
        <Logo>
          <span>GBot</span>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
          >
            {isSidebarOpen ? '◀' : '▶'}
          </Button>
        </Logo>

        <nav>
          {navItems.map(
            (item) =>
              (!item.adminOnly || user?.role === 'admin') && (
                <NavItem
                  key={item.path}
                  href={item.path}
                  active={location.pathname === item.path}
                  onClick={(e) => {
                    e.preventDefault();
                    navigate(item.path);
                  }}
                  whileHover={{ x: 5 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <span>{item.icon}</span>
                  {isSidebarOpen && <span>{item.label}</span>}
                </NavItem>
              )
          )}
        </nav>
      </Sidebar>

      <MainContent sidebarOpen={isSidebarOpen}>
        <Header>
          <h1>{navItems.find((item) => item.path === location.pathname)?.label}</h1>
          <UserInfo>
            <UserName>
              <span>{user?.username}</span>
              <span>{user?.role}</span>
            </UserName>
            <Button variant="ghost" size="sm" onClick={handleLogout}>
              Logout
            </Button>
          </UserInfo>
        </Header>

        <AnimatePresence mode="wait">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            transition={{ duration: 0.2 }}
          >
            {children}
          </motion.div>
        </AnimatePresence>
      </MainContent>
    </LayoutContainer>
  );
};

export default AppLayout;
