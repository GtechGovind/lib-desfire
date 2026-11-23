import type { Args, Command, Field, JsonValue } from './types.ts';
import { parseJson } from './api/schema.ts';

const privateNames = new Set([
  'key',
  'oldkey',
  'newkey',
  'keybytes',
  'keymaterial',
  'secret',
  'secrets',
  'token',
  'sessiontoken',
  'xsessiontoken',
  'authorization',
  'args',
  'request',
  'requestdata',
  'requestpayload',
  'requesthex',
  'tx',
  'txhex',
  'txdata',
]);

export function isSensitiveField(command: Command, field: Field): boolean {
  return Boolean(field.secret) || (command.protocol === 'raw' && field.name === 'data');
}

export function clearSensitiveArgs(command: Command, args: Args): Args {
  const names = new Set(
    command.fields.filter((field) => isSensitiveField(command, field)).map((field) => field.name),
  );
  return Object.fromEntries(
    Object.entries(args).map(([name, value]) => [name, names.has(name) ? '' : value]),
  );
}

export function commandSecrets(command: Command, args: Args): string[] {
  return command.fields
    .filter((field) => isSensitiveField(command, field))
    .map((field) => args[field.name] ?? '')
    .filter(Boolean);
}

export function sanitizeJson(value: JsonValue, secrets: string[] = []): JsonValue {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeJson(item, secrets));
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([name]) => !privateNames.has(name.replace(/[-_]/g, '').toLowerCase()))
        .map(([name, item]) => [name, sanitizeJson(item, secrets)]),
    );
  }
  if (typeof value !== 'string') {
    return value;
  }
  let clean = value;
  for (const secret of secrets
    .filter((item) => item.length >= 2)
    .sort((a, b) => b.length - a.length)) {
    // Match normalized and whitespace-separated hex without retaining the request in activity.
    const normalized = secret.replace(/\s/g, '');
    const escaped = normalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const hexPattern = /^[0-9a-f]+$/i.test(normalized)
      ? normalized.match(/.{1,2}/g)?.join('\\s*')
      : undefined;
    clean = clean.replace(new RegExp(hexPattern ?? escaped, 'gi'), '[redacted]');
  }
  return clean;
}

export function publicJson(value: unknown): string {
  // Responses are scrubbed before state is stored. Scrub names again at export boundaries.
  const json: unknown = JSON.parse(JSON.stringify(value));
  return JSON.stringify(sanitizeJson(parseJson(json)), null, 2);
}
