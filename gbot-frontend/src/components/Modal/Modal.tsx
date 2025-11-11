import React, { useEffect } from 'react';
import styled from '@emotion/styled';
import { motion, AnimatePresence } from 'framer-motion';
import { createPortal } from 'react-dom';

export interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
  closeOnOverlayClick?: boolean;
  closeOnEsc?: boolean;
  showCloseButton?: boolean;
  footer?: React.ReactNode;
}

const ModalOverlay = styled(motion.div)`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: ${({ theme }) => `${theme.current.canvas.default}CC`};
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: ${({ theme }) => theme.zIndices.modal};
  padding: ${({ theme }) => theme.spacing[4]};
`;

const ModalContent = styled(motion.div)<{ size: ModalProps['size'] }>`
  background: ${({ theme }) => theme.current.canvas.default};
  border: 1px solid ${({ theme }) => theme.current.border.default};
  border-radius: ${({ theme }) => theme.radii.lg};
  box-shadow: ${({ theme }) => theme.shadows.xl};
  max-height: calc(100vh - ${({ theme }) => theme.spacing[8]});
  display: flex;
  flex-direction: column;
  position: relative;
  
  ${({ size = 'md', theme }) => {
    switch (size) {
      case 'sm':
        return 'width: 400px;';
      case 'lg':
        return 'width: 800px;';
      case 'xl':
        return 'width: 1100px;';
      case 'full':
        return `
          width: calc(100vw - ${theme.spacing[8]});
          height: calc(100vh - ${theme.spacing[8]});
        `;
      default:
        return 'width: 600px;';
    }
  }}
`;

const ModalHeader = styled.div`
  padding: ${({ theme }) => theme.spacing[4]};
  border-bottom: 1px solid ${({ theme }) => theme.current.border.subtle};
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 60px;
`;

const ModalTitle = styled.h3`
  margin: 0;
  color: ${({ theme }) => theme.current.fg.default};
  font-size: ${({ theme }) => theme.fontSizes.lg};
  font-weight: ${({ theme }) => theme.fontWeights.semibold};
`;

const CloseButton = styled.button`
  background: transparent;
  border: none;
  color: ${({ theme }) => theme.current.fg.muted};
  cursor: pointer;
  padding: ${({ theme }) => theme.spacing[2]};
  border-radius: ${({ theme }) => theme.radii.md};
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all ${({ theme }) => theme.transitions.default};

  &:hover {
    background: ${({ theme }) => theme.current.canvas.subtle};
    color: ${({ theme }) => theme.current.fg.default};
  }

  svg {
    width: 20px;
    height: 20px;
  }
`;

const ModalBody = styled.div`
  padding: ${({ theme }) => theme.spacing[4]};
  overflow-y: auto;
  flex: 1;
`;

const ModalFooter = styled.div`
  padding: ${({ theme }) => theme.spacing[4]};
  border-top: 1px solid ${({ theme }) => theme.current.border.subtle};
  display: flex;
  justify-content: flex-end;
  gap: ${({ theme }) => theme.spacing[2]};
`;

const CloseIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M18 6L6 18M6 6l12 12" />
  </svg>
);

export const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  size = 'md',
  closeOnOverlayClick = true,
  closeOnEsc = true,
  showCloseButton = true,
  footer,
}) => {
  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (isOpen && closeOnEsc && e.key === 'Escape') {
        onClose();
      }
    };

    if (closeOnEsc) {
      document.addEventListener('keydown', handleEsc);
    }

    return () => {
      if (closeOnEsc) {
        document.removeEventListener('keydown', handleEsc);
      }
    };
  }, [isOpen, closeOnEsc, onClose]);

  const modalContent = (
    <AnimatePresence>
      {isOpen && (
        <ModalOverlay
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={closeOnOverlayClick ? onClose : undefined}
        >
          <ModalContent
            size={size}
            onClick={(e) => e.stopPropagation()}
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            transition={{ type: 'spring', duration: 0.3 }}
          >
            <ModalHeader>
              {title && <ModalTitle>{title}</ModalTitle>}
              {showCloseButton && (
                <CloseButton onClick={onClose} aria-label="Close modal">
                  <CloseIcon />
                </CloseButton>
              )}
            </ModalHeader>
            <ModalBody>{children}</ModalBody>
            {footer && <ModalFooter>{footer}</ModalFooter>}
          </ModalContent>
        </ModalOverlay>
      )}
    </AnimatePresence>
  );

  return createPortal(modalContent, document.body);
};

export default Modal;
