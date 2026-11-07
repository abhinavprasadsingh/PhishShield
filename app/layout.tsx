import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishShield | Intelligent Phishing Detection",
  description: "Inspect suspicious URLs and understand phishing warning signals before opening a link.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
