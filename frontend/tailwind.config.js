/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0b0f19',
          card: '#111827',
          panel: '#151e32',
          border: '#1f293d',
          hover: '#1a2642',
          accent: '#3b82f6',
          cyan: '#06b6d4',
          emerald: '#10b981',
          amber: '#f59e0b',
          rose: '#f43f5e',
          purple: '#8b5cf6',
          muted: '#64748b',
          text: '#f1f5f9'
        }
      }
    },
  },
  plugins: [],
}
