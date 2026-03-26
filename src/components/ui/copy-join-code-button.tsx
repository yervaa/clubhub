"use client";

type CopyJoinCodeButtonProps = {
  joinCode: string;
  className?: string;
};

export function CopyJoinCodeButton({ joinCode, className = "" }: CopyJoinCodeButtonProps) {
  const handleCopy = () => {
    navigator.clipboard.writeText(joinCode);
    alert("Join code copied!");
  };

  return (
    <button onClick={handleCopy} className={className}>
      Copy Join Code
    </button>
  );
}