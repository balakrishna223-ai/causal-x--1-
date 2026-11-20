/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        skyBrand: "#38BDF8",
        deepBlue: "#0284C7",
        softSky: "#EFF9FF",
        paleSky: "#E0F2FE",
        sunshine: "#FBBF24",
        warmSunshine: "#FEF3C7",
        ink: "#0F172A",
        mutedInk: "#475569",
      },
      fontFamily: {
        display: ['"Plus Jakarta Sans"', "system-ui", "sans-serif"],
        sans: ['"DM Sans"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
