"use client";

type CTAButtonProps = {
  onClick: () => void;
  children: React.ReactNode;
  className?: string;
};

export function CTAButton({ onClick, children, className = "" }: CTAButtonProps) {
  return (
    <button onClick={onClick} className={className}>
      {children}
    </button>
  );
}
