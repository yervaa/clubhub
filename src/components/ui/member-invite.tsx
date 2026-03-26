"use client";

type MemberInviteProps = {
  joinCode: string;
  membersCount: number;
};

export function MemberInvite({ joinCode, membersCount }: MemberInviteProps) {
  const handleCopyCode = () => {
    navigator.clipboard.writeText(joinCode);
    alert("Join code copied!");
  };

  const isLowMembers = membersCount <= 5;

  return (
    <div className="card-surface p-6">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            <h3 className="text-lg font-semibold text-slate-900">Invite Members</h3>
            {isLowMembers && (
              <span className="inline-flex items-center rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-800">
                Let&apos;s grow!
              </span>
            )}
          </div>
          <p className="text-sm text-slate-600 mb-4">
            Share your club&apos;s join code with friends and classmates to grow your community.
          </p>

          <div className="flex items-center gap-3">
            <div className="flex-1 max-w-xs">
              <div className="rounded-md bg-slate-100 p-3 border border-slate-200">
                <p className="text-center text-lg font-bold tracking-wider text-slate-900">
                  {joinCode}
                </p>
              </div>
            </div>
            <button
              onClick={handleCopyCode}
              className="btn-secondary whitespace-nowrap"
            >
              Copy Code
            </button>
          </div>

          {isLowMembers && (
            <div className="mt-4 rounded-lg bg-blue-50 border border-blue-200 p-3">
              <p className="text-sm text-blue-800">
                💡 <strong>Pro tip:</strong> Share this code in class, on social media, or with friends to get your club started!
              </p>
            </div>
          )}
        </div>

        <div className="flex-shrink-0">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-green-100">
            <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}
