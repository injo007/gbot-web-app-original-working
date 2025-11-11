import React, { useState, useMemo } from 'react';
import styled from '@emotion/styled';
import { motion } from 'framer-motion';
import { Button } from '../Button/Button';

export interface Column<T> {
  key: string;
  title: string;
  render?: (value: any, row: T) => React.ReactNode;
  sortable?: boolean;
  width?: string;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  isLoading?: boolean;
  emptyMessage?: string;
  rowKey?: string;
  onRowClick?: (row: T) => void;
  selectedRows?: string[];
  onSelectionChange?: (selectedKeys: string[]) => void;
  actions?: React.ReactNode;
  pagination?: {
    currentPage: number;
    pageSize: number;
    total: number;
    onPageChange: (page: number) => void;
    onPageSizeChange?: (pageSize: number) => void;
  };
}

const TableWrapper = styled.div`
  position: relative;
  border: 1px solid ${({ theme }) => theme.current.border.default};
  border-radius: ${({ theme }) => theme.radii.lg};
  overflow: hidden;
`;

const TableHeader = styled.div`
  padding: ${({ theme }) => theme.spacing[4]};
  background: ${({ theme }) => theme.current.canvas.subtle};
  border-bottom: 1px solid ${({ theme }) => theme.current.border.default};
  display: flex;
  justify-content: space-between;
  align-items: center;
`;

const Table = styled.table`
  width: 100%;
  border-collapse: collapse;
  background: ${({ theme }) => theme.current.canvas.default};
`;

const Th = styled.th<{ width?: string }>`
  padding: ${({ theme }) => theme.spacing[3]};
  text-align: left;
  font-weight: ${({ theme }) => theme.fontWeights.semibold};
  color: ${({ theme }) => theme.current.fg.muted};
  background: ${({ theme }) => theme.current.canvas.subtle};
  border-bottom: 1px solid ${({ theme }) => theme.current.border.default};
  white-space: nowrap;
  width: ${({ width }) => width || 'auto'};
  user-select: none;
  cursor: pointer;
  transition: background ${({ theme }) => theme.transitions.default};

  &:hover {
    background: ${({ theme }) => theme.current.canvas.inset};
  }
`;

const Td = styled.td`
  padding: ${({ theme }) => theme.spacing[3]};
  border-bottom: 1px solid ${({ theme }) => theme.current.border.subtle};
  color: ${({ theme }) => theme.current.fg.default};
`;

const Tr = styled(motion.tr)<{ isClickable?: boolean; isSelected?: boolean }>`
  background: ${({ theme, isSelected }) =>
    isSelected ? theme.current.canvas.subtle : theme.current.canvas.default};
  cursor: ${({ isClickable }) => (isClickable ? 'pointer' : 'default')};
  transition: background ${({ theme }) => theme.transitions.default};

  &:hover {
    background: ${({ theme }) => theme.current.canvas.subtle};
  }
`;

const EmptyState = styled.div`
  padding: ${({ theme }) => theme.spacing[8]};
  text-align: center;
  color: ${({ theme }) => theme.current.fg.muted};
`;

const LoadingOverlay = styled(motion.div)`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: ${({ theme }) => `${theme.current.canvas.default}80`};
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1;
`;

const Pagination = styled.div`
  padding: ${({ theme }) => theme.spacing[3]};
  background: ${({ theme }) => theme.current.canvas.subtle};
  border-top: 1px solid ${({ theme }) => theme.current.border.default};
  display: flex;
  align-items: center;
  justify-content: space-between;
`;

const PageInfo = styled.div`
  color: ${({ theme }) => theme.current.fg.muted};
  font-size: ${({ theme }) => theme.fontSizes.sm};
`;

const PageSizeSelect = styled.select`
  padding: ${({ theme }) => `${theme.spacing[1]} ${theme.spacing[2]}`};
  border: 1px solid ${({ theme }) => theme.current.border.default};
  border-radius: ${({ theme }) => theme.radii.md};
  background: ${({ theme }) => theme.current.canvas.default};
  color: ${({ theme }) => theme.current.fg.default};
  font-size: ${({ theme }) => theme.fontSizes.sm};
  cursor: pointer;
`;

export function DataTable<T extends Record<string, any>>({
  columns,
  data,
  isLoading,
  emptyMessage = 'No data available',
  rowKey = 'id',
  onRowClick,
  selectedRows = [],
  onSelectionChange,
  actions,
  pagination,
}: DataTableProps<T>) {
  const [sortConfig, setSortConfig] = useState<{
    key: string;
    direction: 'asc' | 'desc';
  } | null>(null);

  const sortedData = useMemo(() => {
    if (!sortConfig) return data;

    return [...data].sort((a, b) => {
      const aValue = a[sortConfig.key];
      const bValue = b[sortConfig.key];

      if (aValue === bValue) return 0;
      if (sortConfig.direction === 'asc') {
        return aValue < bValue ? -1 : 1;
      } else {
        return aValue > bValue ? -1 : 1;
      }
    });
  }, [data, sortConfig]);

  const handleSort = (key: string) => {
    setSortConfig((current) => {
      if (!current || current.key !== key) {
        return { key, direction: 'asc' };
      }
      if (current.direction === 'asc') {
        return { key, direction: 'desc' };
      }
      return null;
    });
  };

  const handleRowClick = (row: T) => {
    if (onSelectionChange) {
      const key = String(row[rowKey]);
      const newSelection = selectedRows.includes(key)
        ? selectedRows.filter((k) => k !== key)
        : [...selectedRows, key];
      onSelectionChange(newSelection);
    }
    onRowClick?.(row);
  };

  return (
    <TableWrapper>
      {actions && <TableHeader>{actions}</TableHeader>}
      <Table>
        <thead>
          <tr>
            {columns.map((column) => (
              <Th
                key={column.key}
                width={column.width}
                onClick={() => column.sortable && handleSort(column.key)}
              >
                {column.title}
                {sortConfig?.key === column.key && (
                  <span>{sortConfig.direction === 'asc' ? ' ↑' : ' ↓'}</span>
                )}
              </Th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sortedData.map((row) => (
            <Tr
              key={row[rowKey]}
              isClickable={!!onRowClick || !!onSelectionChange}
              isSelected={selectedRows.includes(String(row[rowKey]))}
              onClick={() => handleRowClick(row)}
              whileHover={{ scale: onRowClick ? 1.002 : 1 }}
            >
              {columns.map((column) => (
                <Td key={column.key}>
                  {column.render
                    ? column.render(row[column.key], row)
                    : row[column.key]}
                </Td>
              ))}
            </Tr>
          ))}
        </tbody>
      </Table>

      {data.length === 0 && !isLoading && (
        <EmptyState>{emptyMessage}</EmptyState>
      )}

      {pagination && (
        <Pagination>
          <PageInfo>
            Showing {(pagination.currentPage - 1) * pagination.pageSize + 1} to{' '}
            {Math.min(
              pagination.currentPage * pagination.pageSize,
              pagination.total
            )}{' '}
            of {pagination.total} entries
          </PageInfo>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            {pagination.onPageSizeChange && (
              <PageSizeSelect
                value={pagination.pageSize}
                onChange={(e) =>
                  pagination.onPageSizeChange?.(Number(e.target.value))
                }
              >
                <option value="10">10 / page</option>
                <option value="25">25 / page</option>
                <option value="50">50 / page</option>
                <option value="100">100 / page</option>
              </PageSizeSelect>
            )}
            <Button
              size="sm"
              variant="secondary"
              onClick={() => pagination.onPageChange(pagination.currentPage - 1)}
              disabled={pagination.currentPage === 1}
            >
              Previous
            </Button>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => pagination.onPageChange(pagination.currentPage + 1)}
              disabled={
                pagination.currentPage >=
                Math.ceil(pagination.total / pagination.pageSize)
              }
            >
              Next
            </Button>
          </div>
        </Pagination>
      )}

      {isLoading && (
        <LoadingOverlay
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
            style={{
              width: 32,
              height: 32,
              border: '3px solid currentColor',
              borderTopColor: 'transparent',
              borderRadius: '50%',
            }}
          />
        </LoadingOverlay>
      )}
    </TableWrapper>
  );
}
