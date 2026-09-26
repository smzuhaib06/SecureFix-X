import { clsx } from "clsx";

interface CardProps {
  className?: string;
  children: React.ReactNode;
  onClick?: () => void;
  hover?: boolean;
}

export function Card({ className, children, onClick, hover }: CardProps) {
  return (
    <div
      onClick={onClick}
      className={clsx(
        "bg-white rounded-lg border border-slate-200 shadow-sm",
        hover && "cursor-pointer hover:border-blue-300 hover:shadow-md transition-all",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={clsx("px-5 py-4 border-b border-slate-100", className)}>
      {children}
    </div>
  );
}

export function CardBody({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={clsx("px-5 py-4", className)}>{children}</div>
  );
}
