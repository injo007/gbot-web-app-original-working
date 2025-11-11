import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import type { RootState } from '../index';
import type { Toast, Modal } from '../types';

interface UIState {
  toasts: Toast[];
  modals: Modal[];
  isLoading: boolean;
  sidebarOpen: boolean;
  currentView: string | null;
}

const initialState: UIState = {
  toasts: [],
  modals: [],
  isLoading: false,
  sidebarOpen: true,
  currentView: null,
};

export const uiSlice = createSlice({
  name: 'ui',
  initialState,
  reducers: {
    addToast: (state, action: PayloadAction<Omit<Toast, 'id'>>) => {
      const id = Date.now().toString();
      state.toasts.push({ ...action.payload, id });
    },
    removeToast: (state, action: PayloadAction<string>) => {
      state.toasts = state.toasts.filter(toast => toast.id !== action.payload);
    },
    clearToasts: (state) => {
      state.toasts = [];
    },
    openModal: (state, action: PayloadAction<Omit<Modal, 'id'>>) => {
      const id = Date.now().toString();
      state.modals.push({ ...action.payload, id });
    },
    closeModal: (state, action: PayloadAction<string>) => {
      state.modals = state.modals.filter(modal => modal.id !== action.payload);
    },
    closeAllModals: (state) => {
      state.modals = [];
    },
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.isLoading = action.payload;
    },
    toggleSidebar: (state) => {
      state.sidebarOpen = !state.sidebarOpen;
    },
    setSidebarOpen: (state, action: PayloadAction<boolean>) => {
      state.sidebarOpen = action.payload;
    },
    setCurrentView: (state, action: PayloadAction<string | null>) => {
      state.currentView = action.payload;
    },
  },
});

export const {
  addToast,
  removeToast,
  clearToasts,
  openModal,
  closeModal,
  closeAllModals,
  setLoading,
  toggleSidebar,
  setSidebarOpen,
  setCurrentView,
} = uiSlice.actions;

// Selectors
export const selectToasts = (state: RootState) => state.ui.toasts;
export const selectModals = (state: RootState) => state.ui.modals;
export const selectIsLoading = (state: RootState) => state.ui.isLoading;
export const selectSidebarOpen = (state: RootState) => state.ui.sidebarOpen;
export const selectCurrentView = (state: RootState) => state.ui.currentView;

// Helper function to show a toast with default duration
export const showToast = (
  type: Toast['type'],
  message: string,
  duration: number = 5000
) => (dispatch: any) => {
  const toast = { type, message, duration };
  const toastId = dispatch(addToast(toast)).payload.id;
  
  if (duration > 0) {
    setTimeout(() => {
      dispatch(removeToast(toastId));
    }, duration);
  }
};

export default uiSlice.reducer;
