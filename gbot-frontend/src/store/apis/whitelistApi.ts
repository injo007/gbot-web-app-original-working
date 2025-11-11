import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { WhitelistedIP, ApiResponse } from '../types';

interface EmergencyAccessRequest {
  ip: string;
  emergency_key: string;
}

export const whitelistApi = createApi({
  reducerPath: 'whitelistApi',
  baseQuery: fetchBaseQuery({
    baseUrl: '/api/',
    credentials: 'include',
  }),
  tagTypes: ['Whitelist'],
  endpoints: (builder) => ({
    // List whitelisted IPs
    listWhitelistedIPs: builder.query<ApiResponse<WhitelistedIP[]>, void>({
      query: () => 'list-whitelist-ips',
      providesTags: ['Whitelist'],
    }),

    // Add IP to whitelist
    addToWhitelist: builder.mutation<ApiResponse<WhitelistedIP>, string>({
      query: (ip_address) => ({
        url: 'add-whitelist-ip',
        method: 'POST',
        body: { ip_address },
      }),
      invalidatesTags: ['Whitelist'],
    }),

    // Delete IP from whitelist
    deleteFromWhitelist: builder.mutation<ApiResponse<void>, string>({
      query: (ip_address) => ({
        url: 'delete-whitelist-ip',
        method: 'POST',
        body: { ip_address },
      }),
      invalidatesTags: ['Whitelist'],
    }),

    // Delete all IPs from whitelist (admin only)
    deleteAllFromWhitelist: builder.mutation<ApiResponse<void>, void>({
      query: () => ({
        url: 'delete-all-whitelist-ips',
        method: 'POST',
      }),
      invalidatesTags: ['Whitelist'],
    }),

    // Emergency access request
    requestEmergencyAccess: builder.mutation<ApiResponse<{ success: boolean; message: string }>, EmergencyAccessRequest>({
      query: (data) => ({
        url: 'emergency-add-ip',
        method: 'POST',
        body: data,
      }),
    }),

    // Get current IP
    getCurrentIP: builder.query<ApiResponse<{ ip: string }>, void>({
      query: () => 'get-current-ip',
    }),

    // Check if IP is whitelisted
    checkIPWhitelisted: builder.query<ApiResponse<{ whitelisted: boolean }>, string>({
      query: () => `debug-whitelist`,
      transformResponse: (resp: any, _meta, ip_address: string) => {
        const list: string[] = resp?.whitelisted_ips || [];
        return { success: true, data: { whitelisted: list.includes(ip_address) } };
      },
      providesTags: (result, error, ip_address) => [{ type: 'Whitelist', id: ip_address }],
    }),

    // Get whitelist statistics
    getWhitelistStats: builder.query<
      ApiResponse<{
        total_ips: number;
        recent_additions: number;
        recent_deletions: number;
      }>,
      void
    >({
      query: () => 'whitelist-stats',
      providesTags: ['Whitelist'],
    }),
  }),
});

export const {
  useListWhitelistedIPsQuery,
  useAddToWhitelistMutation,
  useDeleteFromWhitelistMutation,
  useDeleteAllFromWhitelistMutation,
  useRequestEmergencyAccessMutation,
  useGetCurrentIPQuery,
  useCheckIPWhitelistedQuery,
  useLazyCheckIPWhitelistedQuery,
  useGetWhitelistStatsQuery,
} = whitelistApi;
