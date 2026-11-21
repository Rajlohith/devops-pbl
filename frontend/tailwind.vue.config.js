/** Tailwind configuration for the Vue application (see postcss.config.js). */
module.exports = {
  content: ['./index.html', './src/**/*.{vue,js}'],
  theme: {
    extend: {
      fontFamily: {
        // System fonts only: no runtime font or CDN dependencies.
        sans: [
          'ui-sans-serif', 'system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"',
          'Roboto', '"Helvetica Neue"', 'Arial', 'sans-serif',
        ],
        mono: [
          'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', '"Liberation Mono"', 'monospace',
        ],
      },
    },
  },
  plugins: [],
}
