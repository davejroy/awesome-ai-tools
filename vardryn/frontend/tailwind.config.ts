import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Vardryn brand palette
        brand: {
          50:  "#eef5ff",
          100: "#d9e8ff",
          200: "#bcd5ff",
          300: "#8eb8ff",
          400: "#598eff",
          500: "#3366ff",
          600: "#1a47f5",
          700: "#1335e1",
          800: "#162cb6",
          900: "#172b8f",
          950: "#111c57",
        },
        surface: {
          950: "#080c14",
          900: "#0d1117",
          800: "#141b27",
          700: "#1c2537",
          600: "#243047",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
    },
  },
  plugins: [],
};

export default config;
