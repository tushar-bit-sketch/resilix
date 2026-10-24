/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        navy: '#10263F',
        techblue: '#2463A6',
        teal: '#138B87',
        surface: '#F3F6FA',
        amberwarn: '#E5A13B',
        critred: '#C84040',
        neutraltext: '#344256',
      },
    },
  },
  plugins: [],
};
