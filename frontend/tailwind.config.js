/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          primary:   "#0a0e1a",
          secondary: "#0f1526",
          card:      "#111827",
          hover:     "#1a2236",
          border:    "#1e293b",
        },
        accent: {
          green:  "#00ff88",
          blue:   "#0ea5e9",
          purple: "#8b5cf6",
        },
        sev: {
          critical: "#dc2626",
          high:     "#ea580c",
          medium:   "#d97706",
          low:      "#2563eb",
          info:     "#6b7280",
        },
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
