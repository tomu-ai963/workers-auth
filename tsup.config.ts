import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    neon: 'src/providers/neon.ts',
    'magic-link': 'src/providers/magic-link.ts',
    'api-key': 'src/providers/api-key.ts',
    'store/kv': 'src/store/kv.ts',
    'store/d1': 'src/store/d1.ts',
    client: 'src/client.ts',
  },
  format: ['esm'],
  target: 'es2022',
  platform: 'neutral',
  dts: true,
  splitting: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  external: ['hono'],
});
