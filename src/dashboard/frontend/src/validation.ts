import type { Args, Command, Credential, Field } from './types.ts';
import { keyType } from './presentation.ts';

type ByteLimit = { name: string; min: number; max: number };
const byteLimits: Record<string, ByteLimit[]> = {
  raw_apdu: [{ name: 'data', min: 4, max: 261 }],
  raw_native: [{ name: 'data', min: 1, max: 256 }],
  iso7816_update_binary: [{ name: 'data', min: 1, max: 255 }],
  iso7816_append_record: [{ name: 'data', min: 1, max: 255 }],
  iso7816_select_by_df_name: [{ name: 'name', min: 1, max: 16 }],
  create_application: [{ name: 'df_name', min: 1, max: 16 }],
};
const keyWidths: Record<string, number> = { des: 16, tdes_2k: 32, tdes_3k: 48, aes_128: 32 };

export function hex(value: string): string {
  return value.replace(/\s/g, '').toUpperCase();
}

export function defaults(command: Command): Args {
  return Object.fromEntries(
    command.fields.map((field) => [field.name, field.secret ? '' : (field.default ?? '')]),
  );
}

export function validateField(field: Field, raw: string): string {
  const value = field.type === 'hex' ? hex(raw) : raw.trim();
  if (value === '') {
    return field.required || (field.type === 'number' && field.required !== false)
      ? 'Required'
      : '';
  }
  if (field.type === 'hex') {
    if (!/^[0-9A-F]+$/.test(value)) {
      return 'Hex digits only';
    }
    if (value.length % 2 !== 0) {
      return 'Complete bytes required';
    }
    if (field.width && value.length !== field.width) {
      return `${field.width / 2} bytes required`;
    }
    if (value.length > 131072) {
      return 'Maximum 65536 bytes';
    }
  }
  if (field.type === 'number') {
    if (!/^-?\d+$/.test(value)) {
      return 'Integer required';
    }
    const number = Number(value);
    if (!Number.isSafeInteger(number)) {
      return 'Integer out of range';
    }
    if (
      (field.min !== undefined && number < field.min) ||
      (field.max !== undefined && number > field.max)
    ) {
      return `${field.min ?? '−∞'} to ${field.max ?? '∞'}`;
    }
  }
  if (field.type === 'select' && !field.options?.includes(value)) {
    return 'Choose a value';
  }
  if (field.type === 'text' && value.length > 1024) {
    return 'Maximum 1024 characters';
  }
  return '';
}

export function validateArgs(
  command: Command,
  args: Args,
  credentials: Credential[] = [],
  selectedAid: string | null = null,
): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const field of command.fields) {
    const error = validateField(field, args[field.name] ?? '');
    if (error) {
      errors[field.name] = error;
    }
  }
  for (const { name, min, max } of byteLimits[command.name] ?? []) {
    const value = hex(args[name] ?? '');
    if (value && !errors[name] && (value.length < min * 2 || value.length > max * 2)) {
      errors[name] = `${min} to ${max} bytes`;
    }
  }
  const authentication = [
    'authenticate',
    'authenticate_iso',
    'authenticate_aes',
    'iso7816_authenticate',
  ].includes(command.name);
  const saved = args.credential_id
    ? credentials.find((item) => item.id === args.credential_id)
    : undefined;
  if (authentication && args.credential_id) {
    if (!saved) {
      errors.credential_id = 'Key not found';
    } else if (hex(saved.aid) !== hex(selectedAid ?? '')) {
      errors.credential_id = `Select AID ${hex(saved.aid)}`;
    }
  }
  if (authentication && !args.credential_id && !hex(args.key ?? '')) {
    errors.key = 'Enter a key or choose a saved key';
  }
  const type =
    saved?.key_type ?? args.key_type ?? (command.name === 'authenticate_aes' ? 'aes_128' : '');
  if (authentication && type) {
    if (command.name === 'authenticate' && !['des', 'tdes_2k'].includes(type)) {
      errors.key_type = 'Use Authenticate AES or Authenticate ISO';
    }
    if (command.name === 'authenticate_iso' && type === 'aes_128') {
      errors.key_type = 'Use Authenticate AES';
    }
    if (command.name === 'authenticate_aes' && type !== 'aes_128') {
      errors.credential_id = 'AES key required';
    }
  }
  for (const name of ['key', 'old_key', 'new_key']) {
    if (!args[name] || (name === 'key' && args.credential_id)) {
      continue;
    }
    const keyKind =
      name === 'old_key'
        ? args.old_type
        : name === 'new_key'
          ? (args.new_type ?? args.key_type)
          : type;
    const width = keyWidths[keyKind];
    if (width && hex(args[name]).length !== width) {
      errors[name] = `${width / 2} bytes required for ${keyType(keyKind)}`;
    }
  }
  if (
    command.name === 'create_value_file' &&
    !['lower_limit', 'upper_limit', 'initial_value'].some((name) => errors[name])
  ) {
    if (Number(args.lower_limit) > Number(args.upper_limit)) {
      errors.upper_limit = 'Below lower limit';
    }
    if (
      Number(args.initial_value) < Number(args.lower_limit) ||
      Number(args.initial_value) > Number(args.upper_limit)
    ) {
      errors.initial_value = 'Outside limits';
    }
  }
  return errors;
}

export function normalizeArgs(command: Command, args: Args): Args {
  return Object.fromEntries(
    command.fields.map((field) => [
      field.name,
      field.type === 'hex' ? hex(args[field.name] ?? '') : (args[field.name] ?? '').trim(),
    ]),
  );
}
