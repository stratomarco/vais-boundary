import { defineConfig } from 'astro/config';

const customDomain = process.env.SITE_URL;
export default defineConfig({
  site: customDomain || 'https://stratomarco.github.io',
  base: customDomain ? '/' : '/vais-boundary',
  output: 'static',
  trailingSlash: 'always',
});
