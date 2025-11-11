// Design tokens based on GitHub Primer CSS and existing GBot styles
export const tokens = {
  colors: {
    // Light theme
    light: {
      canvas: {
        default: '#ffffff',
        subtle: '#f6f8fa',
        inset: '#f6f8fa',
      },
      border: {
        default: '#d0d7de',
        muted: '#d8dee4',
        subtle: 'rgba(27,31,36,0.15)',
      },
      fg: {
        default: '#1f2328',
        muted: '#656d76',
        subtle: '#6e7781',
      },
      accent: {
        fg: '#0969da',
        emphasis: '#0969da',
      },
      success: {
        fg: '#1a7f37',
        emphasis: '#2da44e',
      },
      danger: {
        fg: '#cf222e',
        emphasis: '#da3633',
      },
      warning: {
        fg: '#9a6700',
        emphasis: '#fb8500',
      },
      header: {
        bg: '#24292f',
        text: '#f0f6fc',
      },
      btn: {
        text: '#24292f',
        bg: '#f6f8fa',
        border: '#d0d7de',
        hoverBg: '#f3f4f6',
        hoverBorder: '#afb8c1',
      },
      input: {
        bg: '#ffffff',
        border: '#d0d7de',
      },
      shadow: {
        small: 'rgba(31,35,40,0.04)',
        medium: 'rgba(31,35,40,0.15)',
        large: 'rgba(31,35,40,0.22)',
      },
    },
    // Dark theme
    dark: {
      canvas: {
        default: '#0d1117',
        subtle: '#161b22',
        inset: '#161b22',
      },
      border: {
        default: '#30363d',
        muted: '#21262d',
        subtle: 'rgba(240,246,252,0.1)',
      },
      fg: {
        default: '#e6edf3',
        muted: '#7d8590',
        subtle: '#656d76',
      },
      accent: {
        fg: '#2f81f7',
        emphasis: '#2f81f7',
      },
      success: {
        fg: '#3fb950',
        emphasis: '#238636',
      },
      danger: {
        fg: '#f85149',
        emphasis: '#da3633',
      },
      warning: {
        fg: '#d29922',
        emphasis: '#fb8500',
      },
      header: {
        bg: '#161b22',
        text: '#f0f6fc',
      },
      btn: {
        text: '#c9d1d9',
        bg: '#21262d',
        border: '#30363d',
        hoverBg: '#30363d',
        hoverBorder: '#8b949e',
      },
      input: {
        bg: '#0d1117',
        border: '#30363d',
      },
      shadow: {
        small: 'rgba(1,4,9,0.8)',
        medium: 'rgba(1,4,9,0.8)',
        large: 'rgba(1,4,9,0.8)',
      },
    },
  },
  spacing: {
    0: '0',
    1: '4px',
    2: '8px',
    3: '12px',
    4: '16px',
    5: '20px',
    6: '24px',
    8: '32px',
    10: '40px',
    12: '48px',
    16: '64px',
  },
  fontSizes: {
    xs: '12px',
    sm: '14px',
    md: '16px',
    lg: '18px',
    xl: '20px',
    '2xl': '24px',
    '3xl': '30px',
    '4xl': '36px',
  },
  fontWeights: {
    normal: 400,
    medium: 500,
    semibold: 600,
    bold: 700,
  },
  lineHeights: {
    none: 1,
    tight: 1.25,
    snug: 1.375,
    normal: 1.5,
    relaxed: 1.625,
    loose: 2,
  },
  radii: {
    none: '0',
    sm: '4px',
    md: '6px',
    lg: '8px',
    xl: '12px',
    '2xl': '16px',
    full: '9999px',
  },
  shadows: {
    sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
    md: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
    lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
    xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
  },
  transitions: {
    default: '0.2s ease-in-out',
    fast: '0.1s ease-in-out',
    slow: '0.3s ease-in-out',
  },
  zIndices: {
    hide: -1,
    auto: 'auto',
    base: 0,
    docked: 10,
    dropdown: 1000,
    sticky: 1100,
    banner: 1200,
    overlay: 1300,
    modal: 1400,
    popover: 1500,
    toast: 1600,
    tooltip: 1700,
  },
} as const;
