import type { ApiError, ApiResponse, Command, Session, View } from './types.ts';

export const views: { name: View; title: string; icon: string }[] = [
  { name: 'native', title: 'Native', icon: '⌘' },
  { name: 'iso7816', title: 'ISO 7816', icon: '⎇' },
  { name: 'raw', title: 'Raw', icon: '>_' },
  { name: 'keys', title: 'Keys', icon: '⚿' },
  { name: 'activity', title: 'Activity', icon: '≋' },
];

export function label(value: string): string {
  return value.replace(/\b(aid|uid|iso|picc|aes|df|fids|apdu)\b/gi, (word) => word.toUpperCase());
}

export function keyType(value: string): string {
  const names: Record<string, string> = {
    aes_128: 'AES-128',
    des: 'DES',
    tdes_2k: '2K3DES',
    tdes_3k: '3K3DES',
  };
  return names[value] ?? value;
}

export function commandView(command: Command): View {
  return command.name.startsWith('credential_')
    ? 'keys'
    : command.protocol === 'system'
      ? 'native'
      : command.protocol;
}

export function errorMessage(error?: ApiError): string {
  return error?.message ?? error?.error_code ?? error?.code ?? 'Command failed';
}

export function responseMeta(response: ApiResponse): [string, string][] {
  const entries: [string, string | number | null | undefined][] = [
    ['Native', response.error?.card_status ?? response.result?.card_status],
    ['ISO', response.error?.iso_status ?? response.result?.iso_status],
    ['Delivery', response.error?.delivery ?? response.result?.delivery],
    ['PC/SC', response.error?.reader_error ?? response.result?.reader_error],
  ];
  return entries
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([name, value]) => [name, String(value)]);
}

export function sessionStatus(session: Session | null, ready: boolean, uncertain: boolean): string {
  if (!ready) {
    return 'Offline';
  }
  if (session?.requires_restart) {
    return 'Restart required';
  }
  if (uncertain || session?.requires_reconnect) {
    return 'Reconnect required';
  }
  return session?.connected ? 'Connected' : 'Disconnected';
}

export function commandBlockReason(
  command: Command,
  session: Session | null,
  uncertain: boolean,
): string {
  if (command.protocol === 'system') {
    return command.name === 'connect' && session?.requires_restart
      ? 'Restart console required'
      : '';
  }
  if (session?.requires_restart) {
    return 'Restart console required';
  }
  if (uncertain) {
    return 'Session state uncertain. Reconnect required';
  }
  if (!session?.connected) {
    return 'Connect a reader';
  }
  if (session.requires_reconnect && command.protocol !== 'raw') {
    return 'Reconnect required';
  }
  return '';
}
