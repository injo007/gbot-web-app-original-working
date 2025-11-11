import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { User, ApiResponse } from '../types';

interface CreateUserRequest {
  username: string;
  password: string;
  role: User['role'];
}

interface EditUserRequest extends CreateUserRequest {
  username: string;
}

export const usersApi = createApi({
  reducerPath: 'usersApi',
  baseQuery: fetchBaseQuery({
    baseUrl: '/api/',
    credentials: 'include',
  }),
  tagTypes: ['Users'],
  endpoints: (builder) => ({
    // List all users
    listUsers: builder.query<ApiResponse<User[]>, void>({
      query: () => 'list-users',
      providesTags: ['Users'],
    }),

    // Add new user
    addUser: builder.mutation<ApiResponse<User>, CreateUserRequest>({
      query: (userData) => ({
        url: 'add-user',
        method: 'POST',
        body: userData,
      }),
      invalidatesTags: ['Users'],
    }),

    // Edit existing user
    editUser: builder.mutation<ApiResponse<User>, EditUserRequest>({
      query: (userData) => ({
        url: 'edit-user',
        method: 'POST',
        body: userData,
      }),
      invalidatesTags: ['Users'],
    }),

    // Delete user
    deleteUser: builder.mutation<ApiResponse<void>, string>({
      query: (username) => ({
        url: 'delete-user',
        method: 'POST',
        body: { username },
      }),
      invalidatesTags: ['Users'],
    }),

    // Bulk delete users (admin only)
    bulkDeleteUsers: builder.mutation<ApiResponse<void>, string[]>({
      query: (usernames) => ({
        url: 'bulk-delete-users',
        method: 'POST',
        body: { usernames },
      }),
      invalidatesTags: ['Users'],
    }),

    // Get user details
    getUserDetails: builder.query<ApiResponse<User>, string>({
      query: (username) => `user/${username}`,
      providesTags: (result, error, username) => [{ type: 'Users', id: username }],
    }),
  }),
});

export const {
  useListUsersQuery,
  useAddUserMutation,
  useEditUserMutation,
  useDeleteUserMutation,
  useBulkDeleteUsersMutation,
  useGetUserDetailsQuery,
} = usersApi;
