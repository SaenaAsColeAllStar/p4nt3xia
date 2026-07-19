import type { Metadata } from "next";
import { IBM_Plex_Mono, Instrument_Sans, Instrument_Serif } from "next/font/google";
import "./globals.css";
import { Nav } from "@/components/Nav";

const display = Instrument_Serif({
  subsets: ["latin"],
  weight: "400",
  variable: "--font-display",
});

const sans = Instrument_Sans({
  subsets: ["latin"],
  variable: "--font-sans",
});

const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "P4NT3XIA — Personal Pentest Platform",
  description: "Deep Scan and Attack Mode pentest web application",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${display.variable} ${sans.variable} ${mono.variable}`}>
      <body className="min-h-screen bg-mesh text-ink-900 antialiased">
        <Nav />
        <main className="mx-auto max-w-6xl px-4 pb-16 pt-8 sm:px-6">{children}</main>
      </body>
    </html>
  );
}
