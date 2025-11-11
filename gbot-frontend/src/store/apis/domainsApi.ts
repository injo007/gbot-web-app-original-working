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
      query: () => 'get-domain-usage-stats',
      transformResponse: (resp: any) => {
        const domains = resp?.stats?.domains || [];
        return { success: true, data: domains };
      },
      providesTags: ['Domains'],
    }),

    // Get domain details
    getDomainDetails: builder.query<ApiResponse<Domain>, string>({
      query: () => 'get-domain-usage-stats',
      transformResponse: (resp: any, _meta, domainName: string) => {
        const domains = resp?.stats?.domains || [];
        const found = domains.find((d: any) => d.domain_name === domainName);
        return { success: !!found, data: found };
      },
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
      ApiResponse<{ message: string }>,
      BulkDomainChange
    >({
      query: ({ accounts }) => ({
        url: 'mega-upgrade',
        method: 'POST',
        body: {
          accounts,
          features: { authenticate: true, changeSubdomain: true },
        },
      }),
      transformResponse: (resp: any) => ({
        success: !!resp?.success,
        data: { message: resp?.message || 'Started' },
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
      query: (taskId) => `mega-upgrade-progress/${taskId}`,
      transformResponse: (resp: any) => ({
        success: !!resp?.success,
        data: {
          current: resp?.progress?.completed_accounts ?? 0,
          total: resp?.progress?.total_accounts ?? 0,
          status: (resp?.progress?.status as any) ?? 'processing',
          message: resp?.progress?.progress_message ?? '',
          percentage:
            resp?.progress?.total_accounts
              ? Math.round(
                  ((resp?.progress?.completed_accounts || 0) /
                    resp?.progress?.total_accounts) *
                    100
                )
              : 0,
        },
      }),
    }),

    // Get available domains count
    getAvailableDomainsCount: builder.query<ApiResponse<{ count: number }>, void>({
      query: () => 'get-domain-usage-stats',
      transformResponse: (resp: any) => {
        const domains = resp?.stats?.domains || [];
        const count = domains.filter((d: any) => d.status === 'available').length;
        return { success: true, data: { count } };
      },
      providesTags: ['Domains'],
    }),

    // Get domain usage statistics (map from stats endpoint)
    getDomainStats: builder.query<
      ApiResponse<{
        total_domains: number;
        used_domains: number;
        available_domains: number;
        in_use_domains: number;
      }>,
      void
    >({
      query: () => 'get-domain-usage-stats',
      transformResponse: (resp: any) => {
        const s = resp?.stats || {};
        return {
          success: true,
          data: {
            total_domains: s.total_domains ?? (s.domains || []).length,
            used_domains: s.used_domains ?? 0,
            available_domains: s.available_domains ?? 0,
            in_use_domains: s.in_use_domains ?? 0,
          },
        };
      },
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
