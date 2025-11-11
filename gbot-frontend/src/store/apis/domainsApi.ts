import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { Domain, ApiResponse } from '../types';

interface DomainStatusUpdate {
  subdomain: string;
  status: 'available' | 'in_use' | 'used';
}

interface BulkDomainChange {
  accounts: string[];
  subdomain_prefix?: string;
}

export const domainsApi = createApi({
  reducerPath: 'domainsApi',
  baseQuery: fetchBaseQuery({
    baseUrl: '/api/',
    credentials: 'include',
  }),
  tagTypes: ['Domains'],
  endpoints: (builder) => ({
    // List all domains
    listDomains: builder.query<ApiResponse<Domain[]>, void>({
      query: () => 'list-domains',
      providesTags: ['Domains'],
    }),

    // Get domain details
    getDomainDetails: builder.query<ApiResponse<Domain>, string>({
      query: (domainName) => `domain/${domainName}`,
      providesTags: (result, error, domainName) => [{ type: 'Domains', id: domainName }],
    }),

    // Change domain status
    changeDomainStatus: builder.mutation<ApiResponse<Domain>, DomainStatusUpdate>({
      query: (data) => ({
        url: 'change-subdomain-status',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Domains'],
    }),

    // Mark used domains
    markUsedDomains: builder.mutation<ApiResponse<{ stats: { updated: number; created: number } }>, void>({
      query: () => ({
        url: 'mark-used-domains',
        method: 'POST',
      }),
      invalidatesTags: ['Domains'],
    }),

    // Bulk domain change
    bulkDomainChange: builder.mutation<
      ApiResponse<{
        task_id: string;
        message: string;
      }>,
      BulkDomainChange
    >({
      query: (data) => ({
        url: 'bulk-domain-change',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['Domains'],
    }),

    // Check bulk operation progress
    checkBulkProgress: builder.query<
      ApiResponse<{
        current: number;
        total: number;
        status: 'processing' | 'completed' | 'error';
        message: string;
        percentage: number;
      }>,
      string
    >({
      query: (taskId) => `check-progress/${taskId}`,
    }),

    // Get available domains count
    getAvailableDomainsCount: builder.query<ApiResponse<{ count: number }>, void>({
      query: () => 'available-domains-count',
      providesTags: ['Domains'],
    }),

    // Get domain usage statistics
    getDomainStats: builder.query<
      ApiResponse<{
        total_domains: number;
        used_domains: number;
        available_domains: number;
        in_use_domains: number;
      }>,
      void
    >({
      query: () => 'domain-stats',
      providesTags: ['Domains'],
    }),
  }),
});

export const {
  useListDomainsQuery,
  useGetDomainDetailsQuery,
  useChangeDomainStatusMutation,
  useMarkUsedDomainsMutation,
  useBulkDomainChangeMutation,
  useCheckBulkProgressQuery,
  useGetAvailableDomainsCountQuery,
  useGetDomainStatsQuery,
} = domainsApi;
