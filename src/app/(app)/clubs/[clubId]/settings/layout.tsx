import type { ReactNode } from "react";
import { SettingsSubnav } from "@/components/ui/settings-subnav";

type SettingsLayoutProps = {
  children: ReactNode;
  params: Promise<{ clubId: string }>;
};

export default async function SettingsLayout({ children, params }: SettingsLayoutProps) {
  const { clubId } = await params;

  return (
    <div className="space-y-5">
      <SettingsSubnav clubId={clubId} />
      {children}
    </div>
  );
}
