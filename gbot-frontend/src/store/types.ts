// User types
export interface User {
  username: string;
  role: 'admin' | 'support' | 'mailer';
  emergency?: boolean;
}

// Domain types
export interface Domain {
  domain_name: string;
  user_count: number;
  is_verified: boolean;
  ever_used: boolean;
  created_at: string;
  updated_at: string;
}

// IP Whitelist types
export interface WhitelistedIP {
  ip_address: string;
  added_date: string;
}

// Server Configuration types
export interface ServerConfig {
  host: string;
  port: number;
  username: string;
  auth_method: 'password' | 'key';
  configured_at: string;
}

// API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

// Redux Action types
export interface AsyncThunkConfig {
  state: RootState;
  dispatch: AppDispatch;
  rejectValue: string;
}

// RTK Query types
export interface BaseQueryArgs {
  url: string;
  method?: string;
  body?: any;
  params?: Record<string, string>;
  headers?: Record<string, string>;
}

// Error types
export interface ApiError {
  status: number;
  data: {
    success: false;
    error: string;
    message?: string;
  };
}

// UI types
export interface Toast {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
  duration?: number;
}

export interface Modal {
  id: string;
  type: string;
  props?: Record<string, any>;
}

// Import types from store to avoid circular dependencies
import type { RootState } from './index';
import type { AppDispatch } from './index';
