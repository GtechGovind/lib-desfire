import type {
  ApiError,
  ApiResponse,
  Authentication,
  Bootstrap,
  Command,
  CommandResult,
  Credential,
  Field,
  JsonObject,
  JsonValue,
  Reader,
  ResponseMetadata,
  Session,
} from '../types.ts';

type Guard<T> = (value: unknown) => value is T;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

const isString: Guard<string> = (value): value is string => typeof value === 'string';
const isBoolean: Guard<boolean> = (value): value is boolean => typeof value === 'boolean';
const isNumber: Guard<number> = (value): value is number =>
  typeof value === 'number' && Number.isFinite(value);
const isRevision: Guard<string> = (value): value is string =>
  isString(value) && /^\d+$/.test(value);
const isNullableString: Guard<string | null> = (value): value is string | null =>
  value === null || isString(value);
const isNullableNumber: Guard<number | null> = (value): value is number | null =>
  value === null || isNumber(value);

function oneOf<T extends string>(...choices: T[]): Guard<T> {
  return (value): value is T => choices.some((choice) => choice === value);
}

const isKeyType = oneOf('des', 'tdes_2k', 'tdes_3k', 'aes_128');

function object(value: unknown): Record<string, unknown> {
  if (!isObject(value)) {
    throw new Error('Invalid console response: expected an object.');
  }
  return value;
}

function required<T>(source: Record<string, unknown>, name: string, guard: Guard<T>): T {
  const value = source[name];
  if (!guard(value)) {
    throw new Error(`Invalid console response: ${name}.`);
  }
  return value;
}

function optional<T>(
  source: Record<string, unknown>,
  name: string,
  guard: Guard<T>,
): T | undefined {
  return source[name] === undefined ? undefined : required(source, name, guard);
}

function list<T>(value: unknown, parse: (item: unknown) => T): T[] {
  if (!Array.isArray(value)) {
    throw new Error('Invalid console response: expected an array.');
  }
  return value.map(parse);
}

export function parseJson(value: unknown): JsonValue {
  if (value === null || isString(value) || isBoolean(value) || isNumber(value)) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(parseJson);
  }
  return Object.fromEntries(
    Object.entries(object(value)).map(([name, item]) => [name, parseJson(item)]),
  );
}

function parseField(value: unknown): Field {
  const source = object(value);
  return {
    name: required(source, 'name', isString),
    label: required(source, 'label', isString),
    type: required(source, 'type', oneOf('text', 'hex', 'number', 'select')),
    default: optional(source, 'default', isString),
    width: optional(source, 'width', isNullableNumber),
    min: optional(source, 'min', isNumber),
    max: optional(source, 'max', isNumber),
    required: optional(source, 'required', isBoolean),
    secret: optional(source, 'secret', isBoolean),
    options:
      source.options === undefined
        ? undefined
        : list(source.options, (item) => {
            if (!isString(item)) {
              throw new Error('Invalid console response: field option.');
            }
            return item;
          }),
  };
}

function parseCommand(value: unknown): Command {
  const source = object(value);
  return {
    name: required(source, 'name', isString),
    label: required(source, 'label', isString),
    group: required(source, 'group', isString),
    protocol: required(source, 'protocol', oneOf('system', 'native', 'iso7816', 'raw')),
    mutating: required(source, 'mutating', isBoolean),
    fields: list(source.fields, parseField),
  };
}

function parseAuthentication(value: unknown): Authentication | null {
  if (value === null) {
    return null;
  }
  const source = object(value);
  return {
    protocol: required(source, 'protocol', isString),
    number: required(source, 'number', isNumber),
    key_type: required(source, 'key_type', isKeyType),
    credential_id: required(source, 'credential_id', isNullableString),
  };
}

function parseSession(value: unknown): Session {
  const source = object(value);
  return {
    session_revision: required(source, 'session_revision', isRevision),
    connected: required(source, 'connected', isBoolean),
    reader: required(source, 'reader', isNullableString),
    selected_aid: required(source, 'selected_aid', isNullableString),
    authenticated: parseAuthentication(source.authenticated),
    requires_reconnect: required(source, 'requires_reconnect', isBoolean),
    atr: required(source, 'atr', isString),
    quarantined: optional(source, 'quarantined', isBoolean),
    requires_restart: optional(source, 'requires_restart', isBoolean),
    bridge_available: optional(source, 'bridge_available', isBoolean),
  };
}

function parseCredential(value: unknown): Credential {
  const source = object(value);
  return {
    id: required(source, 'id', isString),
    name: required(source, 'name', isString),
    aid: required(source, 'aid', isString),
    number: required(source, 'number', isNumber),
    key_type: required(source, 'key_type', isKeyType),
    version: required(source, 'version', isString),
  };
}

function parseReader(value: unknown): Reader {
  const source = object(value);
  return {
    name: required(source, 'name', isString),
    card_present: required(source, 'card_present', isBoolean),
    atr: required(source, 'atr', isString),
  };
}

function parseMetadata(source: Record<string, unknown>): ResponseMetadata {
  return {
    card_status: optional(source, 'card_status', isNullableString),
    iso_status: optional(source, 'iso_status', isNullableString),
    delivery: optional(source, 'delivery', isString),
    reader_error: optional(source, 'reader_error', isNullableNumber),
  };
}

function parseError(value: unknown): ApiError | undefined {
  if (value === undefined) {
    return undefined;
  }
  const source = object(value);
  return {
    ...parseMetadata(source),
    message: optional(source, 'message', isString),
    code: optional(source, 'code', isString),
    error_code: optional(source, 'error_code', isString),
  };
}

function parseResult(value: unknown): CommandResult | null | undefined {
  if (value === undefined || value === null) {
    return value;
  }
  const source = object(value);
  const json: JsonObject = Object.fromEntries(
    Object.entries(source).map(([name, item]) => [name, parseJson(item)]),
  );
  // Validate the fields consumed by the UI; retain other command-specific JSON for inspection.
  parseMetadata(source);
  if (source.data !== undefined) {
    required(source, 'data', isString);
  }
  if (source.readers !== undefined) {
    list(source.readers, parseReader);
  }
  if (source.credentials !== undefined) {
    list(source.credentials, parseCredential);
  }
  return json;
}

export function parseResponse(value: unknown): ApiResponse {
  const source = object(value);
  const ok = required(source, 'ok', isBoolean);
  const error = parseError(source.error);
  if (!ok && !error) {
    throw new Error('Invalid console response: missing error.');
  }
  if (ok && (source.state === undefined || source.result === undefined)) {
    throw new Error('Invalid console response: missing command state or result.');
  }
  return {
    ok,
    result: parseResult(source.result),
    state: source.state === undefined ? undefined : parseSession(source.state),
    error,
  };
}

export function parseBootstrap(value: unknown): Bootstrap {
  const source = object(value);
  const commands = list(source.commands, parseCommand);
  if (new Set(commands.map((command) => command.name)).size !== commands.length) {
    throw new Error('Invalid console response: duplicate command.');
  }
  return {
    token: required(source, 'token', isString),
    commands,
    state: parseSession(source.state),
    credentials: list(source.credentials, parseCredential),
    error: parseError(source.error),
  };
}
