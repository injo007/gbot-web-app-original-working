import { configureStore } from '@reduxjs/toolkit';
import { setupListeners } from '@reduxjs/toolkit/query';
import { authApi } from './apis/authApi';
import { usersApi } from './apis/usersApi';
import { domainsApi } from './apis/domainsApi';
import { whitelistApi } from './apis/whitelistApi';
import { settingsApi } from './apis/settingsApi';
import authReducer from './slices/authSlice';
import uiReducer from './slices/uiSlice';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    ui: uiReducer,
    [authApi.reducerPath]: authApi.reducer,
    [usersApi.reducerPath]: usersApi.reducer,
    [domainsApi.reducerPath]: domainsApi.reducer,
    [whitelistApi.reducerPath]: whitelistApi.reducer,
    [settingsApi.reducerPath]: settingsApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(
      authApi.middleware,
      usersApi.middleware,
      domainsApi.middleware,
      whitelistApi.middleware,
      settingsApi.middleware
    ),
});

setupListeners(store.dispatch);

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
