type SectionTitleProps = {
  title: string;
  description?: string;
};

export function SectionTitle({ title, description }: SectionTitleProps) {
  return (
    <div>
      <h2 className="text-lg font-semibold tracking-tight text-slate-900">{title}</h2>
      {description ? <p className="mt-1 text-sm text-slate-600">{description}</p> : null}
    </div>
  );
}
