import { Toaster as Sonner, type ToasterProps } from 'sonner';
import { useTheme } from '@/app/theme';

/** Toasts for mutation results. Sonner renders them in an `aria-live` region. */
function Toaster(props: ToasterProps) {
  const { resolved } = useTheme();
  return (
    <Sonner
      theme={resolved}
      position="bottom-right"
      closeButton
      toastOptions={{
        classNames: {
          toast: 'font-sans !text-sm !rounded-md !border-border !bg-popover !text-popover-foreground !shadow-md',
          description: '!text-muted-foreground',
        },
      }}
      {...props}
    />
  );
}

export { Toaster };
