import rss from '@astrojs/rss';

const posts = Object.values(import.meta.glob('./articles/*.md', { eager: true }))
  .filter((post) => !post.frontmatter.draft);

export function GET(context) {
  return rss({
    title: 'VAIS Boundary',
    description: 'Practical notes on using VAIS Boundary with AI-enabled applications and agents.',
    // context.site omits the base path, which matters on the github.io fallback
    // where the site is served under /vais-boundary/.
    site: new URL(import.meta.env.BASE_URL, context.site),
    items: posts.map((post) => ({
      title: post.frontmatter.title,
      description: post.frontmatter.description,
      pubDate: new Date(post.frontmatter.date),
      link: post.url,
    })),
  });
}
