/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: '#0b1020',
        panel: '#111827',
        brand: '#66d9ef',
        accent: '#9b8cff',
        positive: '#8ef5c0',
        danger: '#ff6b7d',
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(102, 217, 239, 0.2), 0 16px 40px rgba(15, 118, 110, 0.2)',
      },
    },
  },
  plugins: [],
};
