/** @type {import('next').NextConfig} */

// Relative-URL proxy to the FastAPI backend, so the browser only ever talks to
// this Next.js origin. That keeps the dashboard working behind the sandbox
// preview host without hardcoding a localhost URL in client code.
const BACKEND_ORIGIN = process.env.AIDOCTOR_BACKEND_ORIGIN || 'http://127.0.0.1:8000';

// NOTE: Next.js rewrites cannot attach custom request headers. When the
// backend's bearer-token gate is enabled (AIDOCTOR_API_TOKEN), src/middleware.ts
// takes over these same paths and injects the token server-side. The rewrites
// below are the no-token path and remain the default.
const nextConfig = {
  reactStrictMode: false,
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${BACKEND_ORIGIN}/api/:path*`,
      },
      {
        source: '/health',
        destination: `${BACKEND_ORIGIN}/health`,
      },
    ];
  },
};

module.exports = nextConfig;
