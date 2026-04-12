import { JoinClubAuthenticatedContent } from "@/components/join/join-club-authenticated-content";
import { decodeJoinPageMessage, joinMessageIsAlreadyMember } from "@/lib/clubs/join-flow";

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
  const joinCode = typeof params.code === "string" ? params.code.toUpperCase() : "";

  const successMessage = decodeJoinPageMessage(params.success);
  const errorMessage = decodeJoinPageMessage(params.error);
  const isPendingOutcome = params.pending === "1";
  const clubIdParam = typeof params.clubId === "string" ? params.clubId : "";
  const showAlreadyMemberInfo = Boolean(errorMessage && joinMessageIsAlreadyMember(errorMessage));

  return (
    <JoinClubAuthenticatedContent
      joinCode={joinCode}
      successMessage={successMessage}
      errorMessage={errorMessage}
      isPendingOutcome={isPendingOutcome}
      clubIdParam={clubIdParam}
      showAlreadyMemberInfo={showAlreadyMemberInfo}
    />
  );
}
