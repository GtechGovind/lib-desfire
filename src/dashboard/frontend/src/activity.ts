import type { Activity } from './types.ts';
import { publicJson } from './privacy.ts';

export function exportActivity(entries: Activity[]): void {
  const blob = new Blob([publicJson(entries)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `desfire-activity-${new Date().toISOString().replaceAll(':', '-')}.json`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
