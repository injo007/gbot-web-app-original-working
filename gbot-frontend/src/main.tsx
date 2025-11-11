import React from 'react';
import ReactDOM from 'react-dom/client';
import { Global, css } from '@emotion/react';
import App from './App';

// Global styles
const globalStyles = css`
  :root {
    font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI',
      Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
    line-height: 1.5;
    font-weight: 400;
    font-synthesis: none;
    text-rendering: optimizeLegibility;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    -webkit-text-size-adjust: 100%;
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  body {
    margin: 0;
    min-width: 320px;
    min-height: 100vh;
  }

  h1 {
    font-size: 2em;
    line-height: 1.1;
    font-weight: 600;
    margin-bottom: 0.5em;
  }

  h2 {
    font-size: 1.5em;
    line-height: 1.1;
    font-weight: 500;
    margin-bottom: 0.5em;
  }

  h3 {
    font-size: 1.2em;
    line-height: 1.1;
    font-weight: 500;
    margin-bottom: 0.5em;
  }

  p {
    margin-bottom: 1em;
  }

  button {
    font-family: inherit;
  }

  /* Scrollbar styles */
  ::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }

  ::-webkit-scrollbar-track {
    background: transparent;
  }

  ::-webkit-scrollbar-thumb {
    background: #888;
    border-radius: 4px;
  }

  ::-webkit-scrollbar-thumb:hover {
    background: #666;
  }

  /* Selection styles */
  ::selection {
    background: rgba(0, 120, 212, 0.2);
  }

  /* Focus outline styles */
  :focus {
    outline: 2px solid #0078d4;
    outline-offset: 2px;
  }

  :focus:not(:focus-visible) {
    outline: none;
  }

  /* Remove default focus styles for mouse users */
  :focus:not(:focus-visible) {
    outline: none;
  }
`;

// Create root element
const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root element not found');
}

// Create React root and render app
const root = ReactDOM.createRoot(rootElement);

// Render app with global styles
root.render(
  <React.StrictMode>
    <Global styles={globalStyles} />
    <App />
  </React.StrictMode>
);
