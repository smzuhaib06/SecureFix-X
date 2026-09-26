import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SECUREFIX — Detect. Understand. Fix. Verify.",
  description:
    "Autonomous AI engineering workflow for investigating and fixing software security failures.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
