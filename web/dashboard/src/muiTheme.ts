import { createTheme } from '@mui/material/styles';

export const opsTheme = createTheme({
  palette: {
    mode: 'light',
    background: {
      default: '#eef2f6',
      paper: '#ffffff'
    },
    primary: {
      main: '#5aa7ff'
    },
    secondary: {
      main: '#9ddc97'
    },
    warning: {
      main: '#f2b84b'
    },
    error: {
      main: '#ff6b6b'
    },
    success: {
      main: '#66d19e'
    }
  },
  shape: {
    borderRadius: 8
  },
  typography: {
    fontFamily: 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    button: {
      textTransform: 'none',
      fontWeight: 700
    }
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          minHeight: 34
        }
      }
    },
    MuiTextField: {
      defaultProps: {
        size: 'small'
      }
    },
    MuiSelect: {
      defaultProps: {
        size: 'small'
      }
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundImage: 'none'
        }
      }
    }
  }
});
