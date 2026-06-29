import type { Metadata } from 'next';

import './globals.css';

export const metadata: Metadata = {
  title: 'Preflight — dependency dashboard',
  description: 'Pre-flight a dependency manifest: CVEs, framework-lockstep, and auto-update safety.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link
          rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.24.0/dist/tabler-icons.min.css"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
