/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#050a0f',
          card: '#0a1420',
          border: '#0d2137',
          cyan: '#00f5ff',
          blue: '#0080ff',
          green: '#00ff88',
          red: '#ff2d55',
          orange: '#ff9500',
          yellow: '#ffd60a',
          purple: '#bf5af2',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'cyber': '0 0 20px rgba(0, 245, 255, 0.15)',
        'cyber-red': '0 0 20px rgba(255, 45, 85, 0.2)',
        'cyber-green': '0 0 20px rgba(0, 255, 136, 0.15)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 245, 255, 0.2)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 245, 255, 0.6), 0 0 40px rgba(0, 245, 255, 0.2)' },
        }
      }
    },
  },
  plugins: [],
}
