import React, { forwardRef } from 'react';
import styled from '@emotion/styled';
import { motion } from 'framer-motion';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  fullWidth?: boolean;
  isLoading?: boolean;
  variant?: 'outlined' | 'filled';
  size?: 'sm' | 'md' | 'lg';
}

const InputWrapper = styled.div<{ fullWidth?: boolean }>`
  display: inline-flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.spacing[1]};
  width: ${({ fullWidth }) => (fullWidth ? '100%' : 'auto')};
`;

const Label = styled.label`
  color: ${({ theme }) => theme.current.fg.default};
  font-size: ${({ theme }) => theme.fontSizes.sm};
  font-weight: ${({ theme }) => theme.fontWeights.medium};
  margin-bottom: ${({ theme }) => theme.spacing[1]};
`;

const InputContainer = styled.div<{ hasError?: boolean; variant?: string }>`
  position: relative;
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing[2]};
  background: ${({ theme, variant }) =>
    variant === 'filled' ? theme.current.canvas.subtle : theme.current.input.bg};
  border: 1px solid
    ${({ theme, hasError }) =>
      hasError ? theme.current.danger.emphasis : theme.current.input.border};
  border-radius: ${({ theme }) => theme.radii.md};
  transition: all ${({ theme }) => theme.transitions.default};

  &:focus-within {
    border-color: ${({ theme, hasError }) =>
      hasError ? theme.current.danger.emphasis : theme.current.accent.emphasis};
    box-shadow: 0 0 0 2px
      ${({ theme, hasError }) =>
        hasError
          ? `${theme.current.danger.emphasis}20`
          : `${theme.current.accent.emphasis}20`};
  }

  svg {
    color: ${({ theme }) => theme.current.fg.muted};
  }
`;

const StyledInput = styled.input<{ size?: string }>`
  width: 100%;
  background: transparent;
  border: none;
  outline: none;
  color: ${({ theme }) => theme.current.fg.default};
  font-family: inherit;

  &::placeholder {
    color: ${({ theme }) => theme.current.fg.subtle};
  }

  &:disabled {
    cursor: not-allowed;
    opacity: 0.7;
  }

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
`;

const IconWrapper = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  padding: ${({ theme }) => theme.spacing[2]};
`;

const ErrorText = styled(motion.span)`
  color: ${({ theme }) => theme.current.danger.emphasis};
  font-size: ${({ theme }) => theme.fontSizes.xs};
  margin-top: ${({ theme }) => theme.spacing[1]};
`;

const HelperText = styled.span`
  color: ${({ theme }) => theme.current.fg.muted};
  font-size: ${({ theme }) => theme.fontSizes.xs};
  margin-top: ${({ theme }) => theme.spacing[1]};
`;

export const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      error,
      helperText,
      leftIcon,
      rightIcon,
      fullWidth = false,
      isLoading = false,
      variant = 'outlined',
      size = 'md',
      disabled,
      ...props
    },
    ref
  ) => {
    return (
      <InputWrapper fullWidth={fullWidth}>
        {label && <Label>{label}</Label>}
        <InputContainer hasError={!!error} variant={variant}>
          {leftIcon && <IconWrapper>{leftIcon}</IconWrapper>}
          <StyledInput
            ref={ref}
            size={size}
            disabled={disabled || isLoading}
            {...props}
          />
          {rightIcon && <IconWrapper>{rightIcon}</IconWrapper>}
          {isLoading && (
            <IconWrapper>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                style={{
                  width: 16,
                  height: 16,
                  border: '2px solid currentColor',
                  borderTopColor: 'transparent',
                  borderRadius: '50%',
                }}
              />
            </IconWrapper>
          )}
        </InputContainer>
        {error && (
          <ErrorText
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
          >
            {error}
          </ErrorText>
        )}
        {helperText && !error && <HelperText>{helperText}</HelperText>}
      </InputWrapper>
    );
  }
);

Input.displayName = 'Input';

export default Input;
