# VAIS Boundary website

Static Astro landing page and Markdown article support. No database or application server is required. The website is independent of the Python package.

## Preview

Use Node.js 24, then run `npm ci` and `npm run dev` in this folder. Without a Web3Forms key, the contact form explicitly shows a disabled preview. Production deployment refuses to run without the key.

## Launch checklist

1. Register `vaisboundary.com` in the owner's account. This name is proposed, not assumed to be owned.
2. In Web3Forms, create a form for the owner's chosen recipient email and complete email verification. Enable **hCaptcha** in the dashboard's spam protection settings; client-side rendering alone does not enforce it on the server. Do not request file uploads or autoresponders.
3. In this GitHub repository's Settings → Secrets and variables → Actions → Variables, set `PUBLIC_FORM_ACCESS_KEY` to the Web3Forms form access key. Web3Forms access keys are public identifiers embedded in the published HTML; never use a private account API token here.
4. Under Settings → Pages, select **GitHub Actions**. Verify the domain in the GitHub account before connecting it to the repository. Add the exact GitHub-provided TXT verification record at the registrar.
5. For the apex domain, create DNS-only A records for `@` pointing to `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, and `185.199.111.153`. Set `www` as a DNS-only CNAME to `stratomarco.github.io`. Preserve unrelated email and verification records. Do not add wildcard DNS records. Use DNS-only at Cloudflare so GitHub serves its own HTTPS certificate directly.
6. Set the repository's Pages custom domain to `vaisboundary.com` and the Actions variable `SITE_URL` to `https://vaisboundary.com`. Once the certificate is ready, enable **Enforce HTTPS**. GitHub manages the Let's Encrypt certificate automatically.
7. Merge the website change into `dev`. The Website workflow publishes changes under `website/` from that branch. It can also be run manually on `dev` once the workflow is available. Allow `dev` in the `github-pages` environment's deployment rules if needed.
8. Check the real domain, `www` redirect, mobile layout, download link, and article links. Submit one explicitly authorized contact test and verify its arrival in the recipient inbox. No test messages have been sent during initial development.

Domain and contact account setup are required before the site is ready to launch. Before accepting real messages, the maintainer should review the privacy page for their actual retention and contact practices. It is factual explanatory copy, not a legal compliance assessment.

If launching on GitHub's provided address first, leave `SITE_URL` unset. Links and assets use `/vais-boundary/`. When switching to a custom domain, update `SITE_URL` and rebuild.

## Publish an article

Create `src/pages/articles/your-article-title.md` with this frontmatter:

```markdown
---
layout: ../../layouts/Article.astro
title: "Your article title"
description: "One-sentence summary."
date: "2026-09-20"
---

Write your article here using Markdown headings, links, and code blocks.
```

Save and merge into `dev`. Astro generates the article page and adds it to the article list, newest first. Keep unpublished drafts outside `src/pages/`: files inside that folder generate publicly accessible pages even if hidden from the list.

## Branding and scope

The first draft uses a typographic VAIS Boundary wordmark because no standalone logo was found in the supplied repository. The favicon is a simple V and boundary line. No stock images, analytics, or advertising are added. Downloads link to the releases list because published releases are currently prereleases and `/releases/latest` is unavailable.

References: [GitHub custom domains](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site), [GitHub HTTPS](https://docs.github.com/en/pages/getting-started-with-github-pages/securing-your-github-pages-site-with-https), [Web3Forms hCaptcha](https://docs.web3forms.com/getting-started/customizations/spam-protection/hcaptcha).
