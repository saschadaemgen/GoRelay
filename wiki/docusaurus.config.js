// @ts-check

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'GoRelay Documentation',
  tagline: 'Zero-knowledge encrypted relay server for the SimpleGo ecosystem',
  favicon: 'img/favicon.ico',

  url: 'https://wiki.gorelay.dev',
  baseUrl: '/',

  organizationName: 'saschadaemgen',
  projectName: 'GoRelay',

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: '../docs',
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/saschadaemgen/GoRelay/tree/main/wiki/',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'GoRelay',
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'docsSidebar',
            position: 'left',
            label: 'Documentation',
          },
          {
            href: 'https://github.com/saschadaemgen/GoRelay',
            label: 'GitHub',
            position: 'right',
          },
          {
            href: 'https://simplego.dev',
            label: 'SimpleGo',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Documentation',
            items: [
              { label: 'Getting Started', to: '/docs/intro' },
              { label: 'GRP Protocol', to: '/docs/protocol/overview' },
              { label: 'Research', to: '/docs/research/01-smp-server-analysis' },
            ],
          },
          {
            title: 'Ecosystem',
            items: [
              { label: 'SimpleGo', href: 'https://simplego.dev' },
              { label: 'GitHub', href: 'https://github.com/saschadaemgen/GoRelay' },
            ],
          },
	  {
            title: 'Legal',
            items: [
              { label: 'Imprint', to: '/imprint' },
            ],
          },
        ],
        copyright: `Copyright ${new Date().getFullYear()} Sascha Dämgen, IT and More Systems, Recklinghausen. AGPL-3.0.`,
      },
      prism: {
        theme: require('prism-react-renderer').themes.github,
        darkTheme: require('prism-react-renderer').themes.dracula,
        additionalLanguages: ['go', 'bash', 'yaml', 'haskell'],
      },
    }),
};

module.exports = config;
