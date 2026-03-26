"use client";

type ScrollToInputButtonProps = {
  inputSelector: string;
  children: React.ReactNode;
  className?: string;
};

export function ScrollToInputButton({ inputSelector, children, className = "" }: ScrollToInputButtonProps) {
  const handleClick = () => {
    const input = document.querySelector(inputSelector) as HTMLInputElement;
    if (input) {
      input.focus();
      input.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <button onClick={handleClick} className={className}>
      {children}
    </button>
  );
}