/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_API_URL?: string;
  readonly VITE_API_TIMEOUT?: string;

  readonly VITE_ENABLE_MOCK_API?: string;
  readonly VITE_ENABLE_DEBUG_TOOLS?: string;
  readonly VITE_ENABLE_ERROR_REPORTING?: string;

  readonly VITE_AUTH_COOKIE_NAME?: string;
  readonly VITE_AUTH_COOKIE_DOMAIN?: string;

  readonly VITE_APP_NAME?: string;
  readonly VITE_APP_VERSION?: string;
  readonly VITE_APP_ENVIRONMENT?: string;

  readonly VITE_ENABLE_QUERY_CACHE?: string;
  readonly VITE_QUERY_STALE_TIME?: string;
  readonly VITE_QUERY_CACHE_TIME?: string;

  readonly VITE_ENABLE_PERFORMANCE_MONITORING?: string;
  readonly VITE_ENABLE_ERROR_LOGGING?: string;
  readonly VITE_LOG_LEVEL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
