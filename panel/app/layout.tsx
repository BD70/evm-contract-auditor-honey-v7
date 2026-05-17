import type { Metadata } from "next";
import { Providers } from "@/src/components/Providers";
import { AppShell } from "@/src/components/AppShell";

export const metadata: Metadata = {
  title: "EVM Contract Auditor — Admin Panel",
  description: "Operate the EVM contract auditor: runner control, findings explorer, manual audits, rules workbench.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html suppressHydrationWarning lang="en">
      <body>
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
