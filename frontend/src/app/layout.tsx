import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AI Doctor — Autonomous Troubleshooting & Recovery Agent',
  description: 'AWS First Commit Hackathon: Autonomous Incident Detection, Root Cause Diagnosis, and Safe Verified Remediation for Developers.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-slate-950 text-slate-100 antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}
