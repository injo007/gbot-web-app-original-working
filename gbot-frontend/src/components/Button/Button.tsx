import React from 'react';
import styled from '@emotion/styled';
import { motion } from 'framer-motion';
import { useTheme } from '../../theme/ThemeProvider';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  fullWidth?: boolean;
}

const StyledButton = styled(motion.button)<ButtonProps>`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: ${({ theme }) => theme.spacing[2]};
  border-radius: ${({ theme }) => theme.radii.md};
  font-weight: ${({ theme }) => theme.fontWeights.medium};
  transition: all ${({ theme }) => theme.transitions.default};
  cursor: pointer;
  outline: none;
  border: 1px solid transparent;
  width: ${({ fullWidth }) => (fullWidth ? '100%' : 'auto')};

  /* Size variants */
  ${({ size = 'md', theme }) => {
    switch (size) {
      case 'sm':
        return `
          padding: ${theme.spacing[1]} ${theme.spacing[2]};
          font-size: ${theme.fontSizes.xs};
        `;
      case 'lg':
        return `
          padding: ${theme.spacing[3]} ${theme.spacing[4]};
          font-size: ${theme.fontSizes.md};
        `;
      default:
        return `
          padding: ${theme.spacing[2]} ${theme.spacing[3]};
          font-size: ${theme.fontSizes.sm};
        `;
    }
  }}

  /* Style variants */
  ${({ variant = 'primary', theme }) => {
    const colors = theme.current;
    switch (variant) {
      case 'primary':
        return `
          background: ${colors.accent.emphasis};
          color: white;
          &:hover:not(:disabled) {
            background: ${colors.accent.fg};
          }
        `;
      case 'secondary':
        return `
          background: ${colors.btn.bg};
          color: ${colors.btn.text};
          border-color: ${colors.btn.border};
          &:hover:not(:disabled) {
            background: ${colors.btn.hoverBg};
            border-color: ${colors.btn.hoverBorder};
          }
        `;
      case 'danger':
        return `
          background: ${colors.danger.emphasis};
          color: white;
          &:hover:not(:disabled) {
            background: ${colors.danger.fg};
          }
        `;
      case 'ghost':
        return `
          background: transparent;
          color: ${colors.fg.default};
          &:hover:not(:disabled) {
            background: ${colors.canvas.subtle};
          }
        `;
    }
  }}

  /* Disabled state */
  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  /* Loading state */
  ${({ isLoading }) =>
    isLoading &&
    `
    position: relative;
    pointer-events: none;
    
    > * {
      opacity: 0;
    }
  `}
`;

const LoadingSpinner = styled(motion.div)`
  position: absolute;
  width: 16px;
  height: 16px;
  border: 2px solid currentColor;
  border-top-color: transparent;
  border-radius: 50%;
`;

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  leftIcon,
  rightIcon,
  disabled,
  fullWidth = false,
  ...props
}) => {
  const spinnerAnimation = {
    rotate: [0, 360],
    transition: {
      duration: 1,
      repeat: Infinity,
      ease: 'linear',
    },
  };

  return (
    <StyledButton
      variant={variant}
      size={size}
      isLoading={isLoading}
      disabled={disabled || isLoading}
      fullWidth={fullWidth}
      whileTap={{ scale: 0.98 }}
      {...props}
    >
      {leftIcon && <span>{leftIcon}</span>}
      {children}
      {rightIcon && <span>{rightIcon}</span>}
      {isLoading && <LoadingSpinner animate={spinnerAnimation} />}
    </StyledButton>
  );
};

export default Button;
