export type View = 'native' | 'iso7816' | 'raw' | 'keys' | 'activity';
export type Protocol = 'system' | 'native' | 'iso7816' | 'raw';
export type KeyType = 'des' | 'tdes_2k' | 'tdes_3k' | 'aes_128';
export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export type JsonObject = { [name: string]: JsonValue };
export type Field = {
  name: string;
  label: string;
  type: 'text' | 'hex' | 'number' | 'select';
  default?: string;
  width?: number | null;
  min?: number;
  max?: number;
  required?: boolean;
  secret?: boolean;
  options?: string[];
};
export type Command = {
  name: string;
  label: string;
  group: string;
  protocol: Protocol;
  mutating: boolean;
  fields: Field[];
};
export type Args = Record<string, string>;
export type CommandRequest = {
  command: string;
  args: Args;
  confirm: boolean;
  expected_revision?: string;
};
export type Authentication = {
  protocol: string;
  number: number;
  key_type: KeyType;
  credential_id: string | null;
};
export type Session = {
  session_revision: string;
  connected: boolean;
  reader: string | null;
  selected_aid: string | null;
  authenticated: Authentication | null;
  requires_reconnect: boolean;
  atr: string;
  quarantined?: boolean;
  requires_restart?: boolean;
  bridge_available?: boolean;
};
export type Credential = {
  id: string;
  name: string;
  aid: string;
  number: number;
  key_type: KeyType;
  version: string;
};
export type Reader = { name: string; card_present: boolean; atr: string };
export type ResponseMetadata = {
  card_status?: string | null;
  iso_status?: string | null;
  delivery?: string;
  reader_error?: number | null;
};
export type ApiError = ResponseMetadata & { message?: string; code?: string; error_code?: string };
export type CommandResult = JsonObject &
  ResponseMetadata & {
    readers?: Reader[];
    credentials?: Credential[];
    data?: string;
  };
export type ApiResponse = {
  ok: boolean;
  result?: CommandResult | null;
  state?: Session;
  error?: ApiError;
};
export type Bootstrap = {
  token: string;
  commands: Command[];
  state: Session;
  credentials: Credential[];
  error?: ApiError;
};
export type Activity = {
  id: number;
  time: string;
  command: string;
  label: string;
  duration: number;
  response: ApiResponse;
};
