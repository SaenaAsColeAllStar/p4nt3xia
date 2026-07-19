/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#0c1219",
          900: "#141c27",
          800: "#1e2a3a",
          700: "#2a3b52",
          600: "#3d5270",
        },
        fog: {
          50: "#f3f6f9",
          100: "#e6ecf2",
          200: "#c8d4e0",
          300: "#9aadc0",
        },
        signal: {
          DEFAULT: "#1a9f7a",
          dim: "#147a5e",
          bright: "#2ec99a",
        },
        warn: {
          low: "#c9a227",
          medium: "#c46b2b",
          high: "#b8382f",
          critical: "#8b1e2d",
        },
      },
      fontFamily: {
        display: ["var(--font-display)", "Georgia", "serif"],
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      backgroundImage: {
        mesh: `
          radial-gradient(ellipse 80% 50% at 10% -10%, rgba(26,159,122,0.12), transparent 50%),
          radial-gradient(ellipse 60% 40% at 90% 10%, rgba(42,59,82,0.08), transparent 45%),
          linear-gradient(180deg, #f3f6f9 0%, #e6ecf2 100%)
        `,
      },
      keyframes: {
        fadeUp: {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        pulseBar: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.55" },
        },
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(400%)" },
        },
      },
      animation: {
        fadeUp: "fadeUp 0.55s ease-out both",
        pulseBar: "pulseBar 1.6s ease-in-out infinite",
        scanline: "scanline 3.5s linear infinite",
      },
    },
  },
  plugins: [],
};
