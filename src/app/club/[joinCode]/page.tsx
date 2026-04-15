import type { Metadata } from "next";
import { unstable_noStore as noStore } from "next/cache";
import { notFound } from "next/navigation";
import { PublicClubPageView } from "@/components/club/public-club-page-view";
import { Navbar } from "@/components/layout/navbar";
import { getPublicClubPageByJoinCode } from "@/lib/clubs/public-club-page";
import { createClient } from "@/lib/supabase/server";

type PublicClubRouteProps = {
  params: Promise<{ joinCode: string }>;
};

function publicSiteOrigin(): URL | undefined {
  const raw = process.env.NEXT_PUBLIC_SITE_URL?.trim() || process.env.VERCEL_URL?.trim();
  if (!raw) {
    return undefined;
  }
  const withProto = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    return new URL(withProto);
  } catch {
    return undefined;
  }
}

export async function generateMetadata({ params }: PublicClubRouteProps): Promise<Metadata> {
  const { joinCode } = await params;
  const data = await getPublicClubPageByJoinCode(joinCode);
  const metadataBase = publicSiteOrigin();

  if (!data) {
    const title = "Club not found | ClubHub";
    const description =
      "That ClubHub link is not valid. Check the join code or ask your club for a new invite.";
    return {
      metadataBase,
      title,
      description,
      robots: { index: false, follow: true },
      openGraph: {
        title,
        description,
        type: "website",
        siteName: "ClubHub",
      },
      twitter: {
        card: "summary",
        title,
        description,
      },
    };
  }

  const title = `${data.name} | ClubHub`;
  const description =
    data.description.trim().slice(0, 160) ||
    `Learn about ${data.name} and join on ClubHub with your school account.`;

  return {
    metadataBase,
    title,
    description,
    alternates: {
      canonical: `/club/${data.joinCode}`,
    },
    openGraph: {
      title,
      description,
      type: "website",
      siteName: "ClubHub",
      url: `/club/${data.joinCode}`,
    },
    twitter: {
      card: "summary",
      title,
      description,
    },
  };
}

export default async function PublicClubPage({ params }: PublicClubRouteProps) {
  noStore();
  const { joinCode } = await params;
  const data = await getPublicClubPageByJoinCode(joinCode);
  if (!data) {
    notFound();
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main id="main-content" className="page-shell">
        <PublicClubPageView data={data} viewerIsAuthenticated={Boolean(user)} />
      </main>
    </div>
  );
}
