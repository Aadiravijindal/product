import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Recrypt — Post-Quantum Migration Agent',
  description: 'Find, fix, and verify quantum-vulnerable cryptography.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
