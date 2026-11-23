import type { ApiResponse, Bootstrap, CommandRequest } from '../types.ts';
import { sanitizeJson } from '../privacy.ts';
import { parseBootstrap, parseJson, parseResponse } from './schema.ts';

export async function loadBootstrap(signal: AbortSignal): Promise<Bootstrap> {
  const response = await fetch('/api/bootstrap', { cache: 'no-store', signal });
  if (!response.ok) {
    throw new Error(`Console unavailable (HTTP ${response.status}).`);
  }
  const body: unknown = await response.json();
  return parseBootstrap(body);
}

export async function executeCommand(
  token: string,
  request: CommandRequest,
  secrets: string[],
): Promise<ApiResponse> {
  const response = await fetch('/api/command', {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json', 'X-Session-Token': token },
    body: JSON.stringify(request),
  });
  const body: unknown = await response.json();
  const parsed = parseResponse(sanitizeJson(parseJson(body), secrets));
  if (!response.ok && parsed.ok) {
    throw new Error(`Invalid console response (HTTP ${response.status}).`);
  }
  if (response.status >= 500 && !parsed.error?.delivery) {
    return { ...parsed, error: { ...parsed.error, delivery: 'unknown' } };
  }
  return parsed;
}
