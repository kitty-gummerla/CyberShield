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
                cyber: {
                    900: '#0b0f19',
                    800: '#111827',
                    700: '#1f2937',
                    blue: '#3b82f6',
                    teal: '#14b8a6',
                    red: '#ef4444',
                    amber: '#f59e0b',
                    green: '#10b981'
                }
            }
        },
    },
    plugins: [],
}