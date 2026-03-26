"use client";

type CTAButtonProps = {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
};

export function CTAButton({ onClick, children, className = "" }: CTAButtonProps) {
  return (
    <button onClick={onClick} className={className}>
      {children}
    </button>
  );
}
