import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

const customDomain = process.env.SITE_URL;
export default defineConfig({
  site: customDomain || 'https://stratomarco.github.io',
  base: customDomain ? '/' : '/vais-boundary',
  output: 'static',
  trailingSlash: 'always',
  // The form-confirmation page is reachable only after a submission; it has no
  // standalone value in search results.
  integrations: [sitemap({ filter: (page) => !page.endsWith('/thanks/') })],
});
