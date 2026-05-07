import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

import React from 'react';

/**
 * Technical Button component
 */
interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'outline';
  size?: 'xs' | 'sm' | 'md' | 'icon';
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'secondary', size = 'sm', ...props }, ref) => {
    const variants = {
      primary: 'bg-accent-blue text-white hover:bg-blue-600',
      secondary: 'bg-neutral-800 text-neutral-300 hover:bg-neutral-700 border border-neutral-700',
      outline: 'bg-transparent border border-neutral-700 text-neutral-400 hover:text-neutral-200 hover:border-neutral-500',
      ghost: 'bg-transparent text-neutral-400 hover:bg-neutral-800 hover:text-neutral-200',
      danger: 'bg-red-900/20 text-red-400 hover:bg-red-900/40 border border-red-900/50',
    };

    const sizes = {
      xs: 'px-2 py-0.5 text-[11px]',
      sm: 'px-3 py-1 text-xs',
      md: 'px-4 py-2 text-sm',
      icon: 'p-1',
    };

    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center rounded transition-colors focus:outline-none disabled:opacity-50 disabled:pointer-events-none font-medium',
          variants[variant],
          sizes[size],
          className
        )}
        {...props}
      />
    );
  }
);

/**
 * Technical Input component
 */
export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        'w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-1 text-xs text-neutral-200 focus:outline-none focus:border-neutral-600 placeholder:text-neutral-600 transition-colors',
        className
      )}
      {...props}
    />
  )
);

/**
 * Section Heading
 */
export const SectionHeading = ({ children, className }: { children: React.ReactNode; className?: string }) => (
  <h2 className={cn('text-[10px] font-bold uppercase tracking-wider text-neutral-500 mb-2 px-1', className)}>
    {children}
  </h2>
);
