import { getClubAccentColor, getClubInitials, clubAccentTextColor } from "@/lib/clubs/club-visual";

type ClubColorDotProps = {
  clubName: string;
  size?: "sm" | "md";
  className?: string;
};

const sizeClasses = {
  sm: "h-8 w-8 text-[10px]",
  md: "h-9 w-9 text-[11px]",
} as const;

export function ClubColorDot({ clubName, size = "md", className = "" }: ClubColorDotProps) {
  const bg = getClubAccentColor(clubName);
  const fg = clubAccentTextColor(bg);

  return (
    <span
      className={`inline-flex shrink-0 items-center justify-center rounded-full font-bold leading-none ${sizeClasses[size]} ${className}`.trim()}
      style={{ backgroundColor: bg, color: fg }}
      aria-hidden
    >
      {getClubInitials(clubName)}
    </span>
  );
}
