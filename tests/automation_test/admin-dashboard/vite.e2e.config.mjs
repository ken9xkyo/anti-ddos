import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(new URL('../../../web/dashboard/package.json', import.meta.url));
const { defineConfig } = await import(require.resolve('vite'));
const react = (await import(require.resolve('@vitejs/plugin-react'))).default;

const root = fileURLToPath(new URL('../../../web/dashboard', import.meta.url));
const controlUrl = process.env.ANTI_DDOS_TEST_CONTROL_URL || 'http://127.0.0.1:8080';
const port = Number(process.env.ANTI_DDOS_E2E_VITE_PORT || '5173');

export default defineConfig({
  root,
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port,
    strictPort: true,
    proxy: {
      '/v1': controlUrl,
      '/metrics': controlUrl
    }
  }
});

