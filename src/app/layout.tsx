import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ClubHub",
  description: "All your school club activity in one place.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
