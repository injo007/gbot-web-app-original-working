import React from 'react';
import styled from '@emotion/styled';
import { motion } from 'framer-motion';

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'elevated' | 'outlined';
  padding?: 'none' | 'sm' | 'md' | 'lg';
  header?: React.ReactNode;
  footer?: React.ReactNode;
  isLoading?: boolean;
  isInteractive?: boolean;
}

const StyledCard = styled(motion.div)<CardProps>`
  background: ${({ theme }) => theme.current.canvas.default};
  border-radius: ${({ theme }) => theme.radii.lg};
  overflow: hidden;
  position: relative;

  /* Variant styles */
  ${({ variant = 'default', theme }) => {
    switch (variant) {
      case 'elevated':
        return `
          box-shadow: ${theme.shadows.md};
          border: 1px solid ${theme.current.border.subtle};
        `;
      case 'outlined':
        return `
          border: 1px solid ${theme.current.border.default};
        `;
      default:
        return `
          border: 1px solid ${theme.current.border.subtle};
        `;
    }
  }}

  /* Interactive state */
  ${({ isInteractive, theme }) =>
    isInteractive &&
    `
    cursor: pointer;
    transition: all ${theme.transitions.default};

    &:hover {
      transform: translateY(-2px);
      box-shadow: ${theme.shadows.lg};
    }

    &:active {
      transform: translateY(0);
    }
  `}
`;

const CardHeader = styled.div`
  padding: ${({ theme }) => theme.spacing[4]};
  border-bottom: 1px solid ${({ theme }) => theme.current.border.subtle};
`;

const CardContent = styled.div<{ padding?: CardProps['padding'] }>`
  ${({ padding = 'md', theme }) => {
    switch (padding) {
      case 'none':
        return 'padding: 0;';
      case 'sm':
        return `padding: ${theme.spacing[2]};`;
      case 'lg':
        return `padding: ${theme.spacing[6]};`;
      default:
        return `padding: ${theme.spacing[4]};`;
    }
  }}
`;

const CardFooter = styled.div`
  padding: ${({ theme }) => theme.spacing[4]};
  border-top: 1px solid ${({ theme }) => theme.current.border.subtle};
`;

const LoadingOverlay = styled(motion.div)`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: ${({ theme }) => theme.current.canvas.default}80;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1;
`;

const LoadingSpinner = styled(motion.div)`
  width: 24px;
  height: 24px;
  border: 2px solid ${({ theme }) => theme.current.accent.emphasis};
  border-top-color: transparent;
  border-radius: 50%;
`;

export const Card: React.FC<CardProps> = ({
  children,
  variant = 'default',
  padding = 'md',
  header,
  footer,
  isLoading = false,
  isInteractive = false,
  ...props
}) => {
  return (
    <StyledCard
      variant={variant}
      isInteractive={isInteractive}
      initial={isInteractive ? { y: 0 } : undefined}
      whileHover={isInteractive ? { y: -2 } : undefined}
      whileTap={isInteractive ? { y: 0 } : undefined}
      {...props}
    >
      {header && <CardHeader>{header}</CardHeader>}
      <CardContent padding={padding}>{children}</CardContent>
      {footer && <CardFooter>{footer}</CardFooter>}
      {isLoading && (
        <LoadingOverlay
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          <LoadingSpinner
            animate={{ rotate: 360 }}
            transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          />
        </LoadingOverlay>
      )}
    </StyledCard>
  );
};

export default Card;
