// SPDX-License-Identifier: Apache-2.0
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
        // Dark theme tokens (OLED / Slate)
        dark: {
          bg: '#090a0f',
          surface: '#11141d',
          card: '#161a26',
          header: '#0e111a',
          sidebar: '#0b0e14',
          border: '#232838',
          borderLight: '#30364d',
          text: '#f0f3f8',
          muted: '#8b94a7',
          hover: '#1d2232',
        },
        // Light theme tokens (Apple / Google Material 3)
        light: {
          bg: '#f6f8fa',
          surface: '#ffffff',
          card: '#ffffff',
          header: '#ffffff',
          sidebar: '#fcfdfe',
          border: '#e2e6ed',
          borderLight: '#ebeef3',
          text: '#1a1f2c',
          muted: '#626d7f',
          hover: '#f1f4f8',
        },
        // Priority Tiers
        p1: {
          DEFAULT: '#ef4444',
          light: '#dc2626',
          dark: '#f87171',
        },
        p2: {
          DEFAULT: '#f59e0b',
          light: '#d97706',
          dark: '#fbbf24',
        },
        p3: {
          DEFAULT: '#0284c7',
          light: '#0369a1',
          dark: '#38bdf8',
        },
        p4: {
          DEFAULT: '#10b981',
          light: '#059669',
          dark: '#34d399',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          'Inter',
          'SF Pro Text',
          'Segoe UI',
          'Roboto',
          'system-ui',
          'sans-serif',
        ],
      },
      boxShadow: {
        'glass-dark': '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
        'glass-light': '0 8px 30px 0 rgba(0, 0, 0, 0.05)',
        'subtle': '0 1px 3px 0 rgba(0, 0, 0, 0.08), 0 1px 2px 0 rgba(0, 0, 0, 0.04)',
        'elevated': '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)',
        'drawer': '-10px 0 40px rgba(0, 0, 0, 0.3)',
      },
      animation: {
        'pulse-subtle': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'radar-sweep': 'radar 3s linear infinite',
      },
      keyframes: {
        radar: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        }
      }
    },
  },
  plugins: [],
}

