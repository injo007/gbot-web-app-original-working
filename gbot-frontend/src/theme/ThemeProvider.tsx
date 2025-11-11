import React, { createContext, useContext, useEffect, useState } from 'react';
import { ThemeProvider as EmotionThemeProvider } from '@emotion/react';
import { tokens } from './tokens';

type ThemeMode = 'light' | 'dark';

interface ThemeContextType {
  mode: ThemeMode;
  toggleTheme: () => void;
  theme: typeof tokens;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

interface ThemeProviderProps {
  children: React.ReactNode;
}

export const ThemeProvider: React.FC<ThemeProviderProps> = ({ children }) => {
  // Initialize theme from localStorage or system preference
  const [mode, setMode] = useState<ThemeMode>(() => {
    const savedMode = localStorage.getItem('theme');
    if (savedMode === 'light' || savedMode === 'dark') {
      return savedMode;
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  });

  // Update theme when system preference changes
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e: MediaQueryListEvent) => {
      if (!localStorage.getItem('theme')) {
        setMode(e.matches ? 'dark' : 'light');
      }
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  // Update document attributes and localStorage when theme changes
  useEffect(() => {
    document.documentElement.setAttribute('data-color-mode', mode);
    localStorage.setItem('theme', mode);
  }, [mode]);

  const toggleTheme = () => {
    setMode(prev => prev === 'dark' ? 'light' : 'dark');
  };

  // Combine theme tokens with current mode
  const theme = {
    ...tokens,
    current: tokens.colors[mode],
  };

  const value = {
    mode,
    toggleTheme,
    theme,
  };

  return (
    <ThemeContext.Provider value={value}>
      <EmotionThemeProvider theme={theme}>
        {children}
      </EmotionThemeProvider>
    </ThemeContext.Provider>
  );
};

// Type definitions for emotion theme
declare module '@emotion/react' {
  export interface Theme {
    colors: typeof tokens.colors;
    current: typeof tokens.colors.light | typeof tokens.colors.dark;
    spacing: typeof tokens.spacing;
    fontSizes: typeof tokens.fontSizes;
    fontWeights: typeof tokens.fontWeights;
    lineHeights: typeof tokens.lineHeights;
    radii: typeof tokens.radii;
    shadows: typeof tokens.shadows;
    transitions: typeof tokens.transitions;
    zIndices: typeof tokens.zIndices;
  }
}
