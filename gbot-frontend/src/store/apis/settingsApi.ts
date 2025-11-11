import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { ServerConfig, ApiResponse } from '../types';

interface OTPConfig {
  host: string;
  port: number;
  username: string;
  auth_method: 'password' | 'key';
  password?: string;
  private_key?: string;
}

interface TestConnectionResponse {
  success: boolean;
  message: string;
  details?: {
    connected: boolean;
    auth_success: boolean;
    file_access: boolean;
  };
}

export const settingsApi = createApi({
  reducerPath: 'settingsApi',
  baseQuery: fetchBaseQuery({
    baseUrl: '/api/',
    credentials: 'include',
  }),
  tagTypes: ['Settings', 'OTPConfig'],
  endpoints: (builder) => ({
    // Server Configuration
    getServerConfig: builder.query<ApiResponse<ServerConfig>, void>({
      query: () => 'get-server-config',
      providesTags: ['Settings'],
    }),

    saveServerConfig: builder.mutation<ApiResponse<ServerConfig>, Partial<ServerConfig>>({
      query: (config) => ({
        url: 'save-server-config',
        method: 'POST',
        body: config,
      }),
      invalidatesTags: ['Settings'],
    }),

    testServerConnection: builder.mutation<TestConnectionResponse, Partial<ServerConfig>>({
      query: (config) => ({
        url: 'test-server-connection',
        method: 'POST',
        body: config,
      }),
    }),

    // OTP Configuration
    getOTPConfig: builder.query<ApiResponse<OTPConfig>, void>({
      query: () => 'get-otp-ssh-config',
      providesTags: ['OTPConfig'],
    }),

    saveOTPConfig: builder.mutation<ApiResponse<OTPConfig>, Partial<OTPConfig>>({
      query: (config) => ({
        url: 'save-otp-ssh-config',
        method: 'POST',
        body: config,
      }),
      invalidatesTags: ['OTPConfig'],
    }),

    testOTPConnection: builder.mutation<TestConnectionResponse, Partial<OTPConfig>>({
      query: (config) => ({
        url: 'test-otp-server-connection',
        method: 'POST',
        body: config,
      }),
    }),

    // Database Operations
    createBackup: builder.mutation<ApiResponse<{ filename: string; size: number }>, void>({
      query: () => ({
        url: 'create-database-backup',
        method: 'POST',
        body: { format: 'sql', include_data: 'full' },
      }),
      transformResponse: (resp: any) => ({
        success: !!resp?.success,
        data: { filename: resp?.filename, size: resp?.size },
        message: resp?.message,
      }),
    }),

    restoreBackup: builder.mutation<ApiResponse<{ success: boolean; message: string }>, FormData>({
      query: (data) => ({
        url: 'upload-restore-backup',
        method: 'POST',
        body: data,
      }),
    }),

    getBackupsList: builder.query<ApiResponse<{ backups: string[] }>, void>({
      query: () => 'list-database-backups',
      transformResponse: (resp: any) => ({
        success: !!resp?.success,
        data: { backups: (resp?.files || []).map((f: any) => f.name) },
      }),
    }),

    // System Health Check
    checkSystemHealth: builder.query<
      ApiResponse<{
        database: boolean;
        server_connection: boolean;
        otp_connection: boolean;
        disk_space: {
          available: number;
          total: number;
          used_percentage: number;
        };
      }>,
      void
    >({
      query: () => 'diagnose-backup',
      transformResponse: (resp: any) => {
        const diag = resp?.diagnosis || {};
        const dbOk = (diag.database?.connection || '').toString().toUpperCase() === 'OK';
        return {
          success: !!resp?.success,
          data: {
            database: dbOk,
            server_connection: true,
            otp_connection: false,
            disk_space: { available: 0, total: 0, used_percentage: 0 },
          },
        };
      },
    }),
  }),
});

export const {
  useGetServerConfigQuery,
  useSaveServerConfigMutation,
  useTestServerConnectionMutation,
  useGetOTPConfigQuery,
  useSaveOTPConfigMutation,
  useTestOTPConnectionMutation,
  useCreateBackupMutation,
  useRestoreBackupMutation,
  useGetBackupsListQuery,
  useCheckSystemHealthQuery,
} = settingsApi;
