import type { Metadata } from "next";
import "./globals.css";

// Deliberately no next/font: the palette specifies the system UI sans, and this
// tool is meant to run on a LAN with no internet reachability.
export const metadata: Metadata = {
  title: "Local network diagnostics",
  description:
    "Repeatable discovery and health check of the local network — devices, services, connectivity and Wi-Fi.",
};

// Typed explicitly rather than via Next's generated `LayoutProps`, so a clean
// checkout typechecks before `next build` has generated its route types.
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="flex min-h-full flex-col">{children}</body>
    </html>
  );
}
