import { useEffect } from 'react';
import type { RefObject } from 'react';

export function useKeyboardShortcuts(
  enabled: boolean,
  search: RefObject<HTMLInputElement | null>,
  form: RefObject<HTMLFormElement | null>,
) {
  useEffect(() => {
    function handleKey(event: KeyboardEvent) {
      if (!enabled) {
        return;
      }
      const target = event.target;
      const editable =
        target instanceof HTMLElement &&
        (['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) || target.isContentEditable);
      if (event.key === '/' && !editable) {
        event.preventDefault();
        search.current?.focus();
      }
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        form.current?.requestSubmit();
      }
    }
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [enabled, form, search]);
}
