import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement>;

const stroke = {
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

/** Tabler-style outline icons (24px) for the icon sidebar. */
export function NavIconHome(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} aria-hidden {...stroke} {...props}>
      <path d="M5 12l-2 0l0 -9l7 0l0 4" />
      <path d="M19 12l2 0l0 -9l-7 0l0 4" />
      <path d="M4 21l16 0" />
      <path d="M9 21v-6a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v6" />
    </svg>
  );
}

export function NavIconUsers(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} aria-hidden {...stroke} {...props}>
      <path d="M9 7m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0" />
      <path d="M3 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
      <path d="M21 21v-2a4 4 0 0 0 -3 -3.85" />
    </svg>
  );
}

export function NavIconCalendarEvent(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} aria-hidden {...stroke} {...props}>
      <path d="M4 7a2 2 0 0 1 2 -2h12a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12z" />
      <path d="M16 3v4" />
      <path d="M8 3v4" />
      <path d="M4 11h16" />
      <path d="M8 15h2v2h-2z" />
    </svg>
  );
}

export function NavIconSpeakerphone(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} aria-hidden {...stroke} {...props}>
      <path d="M18 8a3 3 0 0 1 0 6" />
      <path d="M10 8v6a2 2 0 0 0 2 2h1l4 4v-16l-4 4h-1a2 2 0 0 0 -2 2z" />
    </svg>
  );
}

export function NavIconActivity(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} aria-hidden {...stroke} {...props}>
      <path d="M3 12h4l3 8l4 -16l3 8h4" />
    </svg>
  );
}

export function NavIconSettings(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} aria-hidden {...stroke} {...props}>
      <path d="M10.325 4.317c.426 -1.756 2.924 -1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543 -.94 3.31 .826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.756 .426 1.756 2.924 0 3.35a1.724 1.724 0 0 0 -1.066 2.573c.94 1.543 -.826 3.31 -2.37 2.37a1.724 1.724 0 0 0 -2.572 1.065c-.426 1.756 -2.924 1.756 -3.35 0a1.724 1.724 0 0 0 -2.573 -1.066c-1.543 .94 -3.31 -.826 -2.37 -2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756 -.426 -1.756 -2.924 0 -3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94 -1.543 .826 -3.31 2.37 -2.37c1 .608 2.296 .07 2.572 -1.065z" />
      <path d="M9 12a3 3 0 1 0 6 0a3 3 0 0 0 -6 0" />
    </svg>
  );
}

export type NavIconName = "home" | "users" | "calendar-event" | "speakerphone" | "activity" | "settings";

export function NavIcon({ name, ...props }: { name: NavIconName } & IconProps) {
  switch (name) {
    case "home":
      return <NavIconHome {...props} />;
    case "users":
      return <NavIconUsers {...props} />;
    case "calendar-event":
      return <NavIconCalendarEvent {...props} />;
    case "speakerphone":
      return <NavIconSpeakerphone {...props} />;
    case "activity":
      return <NavIconActivity {...props} />;
    case "settings":
      return <NavIconSettings {...props} />;
    default:
      return <NavIconHome {...props} />;
  }
}
