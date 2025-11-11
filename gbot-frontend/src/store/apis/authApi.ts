import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { setUser, logout } from '../slices/authSlice';
import type { User } from '../types';

interface LoginRequest {
  username: string;
  password: string;
}

interface LoginResponse {
  success: boolean;
  user?: User;
  error?: string;
}

export const authApi = createApi({
  reducerPath: 'authApi',
  baseQuery: fetchBaseQuery({
    baseUrl: '/',
    credentials: 'include', // Important: Include cookies for session management
  }),
  endpoints: (builder) => ({
    login: builder.mutation<LoginResponse, LoginRequest>({
      query: (credentials) => ({
        url: 'login',
        method: 'POST',
        body: credentials,
      }),
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled;
          if (data.success && data.user) {
            dispatch(setUser(data.user));
          }
        } catch (error) {
          console.error('Login error:', error);
        }
      },
    }),

    logout: builder.mutation<void, void>({
      query: () => ({
        url: 'logout',
        method: 'POST',
      }),
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          await queryFulfilled;
          dispatch(logout());
        } catch (error) {
          console.error('Logout error:', error);
        }
      },
    }),

    // Check current session status
    checkAuth: builder.query<LoginResponse, void>({
      query: () => 'api/check-auth',
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled;
          if (data.success && data.user) {
            dispatch(setUser(data.user));
          } else {
            dispatch(logout());
          }
        } catch (error) {
          console.error('Auth check error:', error);
          dispatch(logout());
        }
      },
    }),

    // Emergency access endpoint
    emergencyAccess: builder.mutation<LoginResponse, { ip: string; token: string }>({
      query: (data) => ({
        url: 'emergency_access',
        method: 'POST',
        body: data,
      }),
      async onQueryStarted(_, { dispatch, queryFulfilled }) {
        try {
          const { data } = await queryFulfilled;
          if (data.success && data.user) {
            dispatch(setUser({ ...data.user, emergency: true }));
          }
        } catch (error) {
          console.error('Emergency access error:', error);
        }
      },
    }),
  }),
});

export const {
  useLoginMutation,
  useLogoutMutation,
  useCheckAuthQuery,
  useEmergencyAccessMutation,
} = authApi;
