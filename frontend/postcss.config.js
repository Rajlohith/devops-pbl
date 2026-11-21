const path = require('node:path')

module.exports = {
  plugins: {
    // The Vue app has its own Tailwind config; tailwind.config.js still belongs to the legacy
    // Flask pages (`npm run build:css`).
    tailwindcss: { config: path.join(__dirname, 'tailwind.vue.config.js') },
    autoprefixer: {},
  },
}
