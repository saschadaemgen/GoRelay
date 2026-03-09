// @ts-check
import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'GoRelay',
  tagline: 'Secure Dual Relay Infrastructure',
  favicon: 'https://simplego.dev/favicon-32.png',
  url: 'https://wiki.gorelay.dev',
  baseUrl: '/',
  organizationName: 'saschadaemgen',
  projectName: 'GoRelay',
  onBrokenLinks: 'throw',
  markdown: {
    format: 'detect',
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      ({
        docs: {
          path: '../docs',
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/saschadaemgen/GoRelay/edit/main/docs/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig: ({
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: true,
      respectPrefersColorScheme: false,
    },
    navbar: {
      title: '',
      logo: {
        alt: 'GoRelay',
        src: 'img/logo.png',
        href: '/docs/intro',
        target: '_self',
      },
      items: [
        {href: 'https://simplego.dev', label: 'SimpleGo', position: 'right'},
        {href: 'https://github.com/saschadaemgen/GoRelay', label: 'GitHub', position: 'right'},
      ],
    },
    footer: {
      style: 'dark',
      links: [],
    },
    prism: {
      theme: prismThemes.oneDark,
      darkTheme: prismThemes.oneDark,
      additionalLanguages: ['go', 'bash', 'powershell', 'haskell', 'yaml'],
    },
    docs: {
      sidebar: {
        hideable: true,
        autoCollapseCategories: true,
      },
    },
  }),
};

export default config;
