import { redirect } from "next/navigation";

type JoinClubPageProps = {
  searchParams: Promise<{
    code?: string;
    error?: string;
    success?: string;
    clubId?: string;
    pending?: string;
  }>;
};

export default async function JoinClubPage({ searchParams }: JoinClubPageProps) {
  const params = await searchParams;
  const next = new URLSearchParams();
  if (params.code) next.set("code", params.code);
  if (params.error) next.set("error", params.error);
  if (params.success) next.set("success", params.success);
  if (params.clubId) next.set("clubId", params.clubId);
  if (params.pending) next.set("pending", params.pending);
  redirect(`/join${next.size ? `?${next.toString()}` : ""}`);
}
