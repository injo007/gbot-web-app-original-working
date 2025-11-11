import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import { store } from '../store';
import { logout, setError } from '../store/slices/authSlice';
import { showToast } from '../store/slices/uiSlice';

// Create axios instance with default config
const client: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Important for session cookie handling
});

// Request interceptor
client.interceptors.request.use(
  (config: AxiosRequestConfig) => {
    // You can add custom headers here if needed
    return config;
  },
  (error: AxiosError) => {
    return Promise.reject(error);
  }
);

// Response interceptor
client.interceptors.response.use(
  (response: AxiosResponse) => {
    return response;
  },
  async (error: AxiosError) => {
    const { response } = error;

    // Handle different error scenarios
    if (response?.status === 401) {
      // Unauthorized - clear auth state
      store.dispatch(logout());
      store.dispatch(showToast('error', 'Session expired. Please log in again.'));
    } else if (response?.status === 403) {
      // Forbidden - user doesn't have required permissions
      store.dispatch(setError('You do not have permission to perform this action.'));
      store.dispatch(showToast('error', 'Permission denied'));
    } else if (response?.status === 404) {
      // Not found
      store.dispatch(showToast('error', 'Resource not found'));
    } else if (response?.status === 500) {
      // Server error
      store.dispatch(showToast('error', 'An unexpected error occurred. Please try again later.'));
    }

    return Promise.reject(error);
  }
);

// API request helpers
export const api = {
  get: <T>(url: string, config?: AxiosRequestConfig) =>
    client.get<T>(url, config).then((response) => response.data),

  post: <T>(url: string, data?: any, config?: AxiosRequestConfig) =>
    client.post<T>(url, data, config).then((response) => response.data),

  put: <T>(url: string, data?: any, config?: AxiosRequestConfig) =>
    client.put<T>(url, data, config).then((response) => response.data),

  delete: <T>(url: string, config?: AxiosRequestConfig) =>
    client.delete<T>(url, config).then((response) => response.data),

  // File upload helper
  upload: (url: string, file: File, onProgress?: (percentage: number) => void) => {
    const formData = new FormData();
    formData.append('file', file);

    return client.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const percentage = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress(percentage);
        }
      },
    });
  },

  // Bulk operation helper with progress tracking
  bulkOperation: async <T>(
    items: any[],
    operationFn: (item: any) => Promise<T>,
    onProgress?: (current: number, total: number) => void
  ) => {
    const results: T[] = [];
    const total = items.length;

    for (let i = 0; i < total; i++) {
      const result = await operationFn(items[i]);
      results.push(result);
      onProgress?.(i + 1, total);
    }

    return results;
  },
};

// Error handling utilities
export const isAxiosError = axios.isAxiosError;

export const getErrorMessage = (error: unknown): string => {
  if (isAxiosError(error)) {
    return error.response?.data?.error || error.response?.data?.message || error.message;
  }
  return error instanceof Error ? error.message : 'An unknown error occurred';
};

// Type definitions
export interface ApiError {
  status: number;
  message: string;
  errors?: Record<string, string[]>;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export default client;
