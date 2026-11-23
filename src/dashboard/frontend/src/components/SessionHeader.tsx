import { keyType, sessionStatus } from '../presentation.ts';
import type { Args, Reader, Session } from '../types.ts';

type Props = {
  session: Session | null;
  readers: Reader[];
  reader: string;
  setReader: (name: string) => void;
  busy: boolean;
  ready: boolean;
  uncertain: boolean;
  send: (name: string, args?: Args) => void;
};

export function SessionHeader({
  session,
  readers,
  reader,
  setReader,
  busy,
  ready,
  uncertain,
  send,
}: Props) {
  const reconnect = session?.requires_reconnect || uncertain;
  const auth = session?.authenticated;
  const authLabel = auth
    ? `${keyType(auth.key_type)} · Key ${auth.number} · ${auth.protocol}`
    : session?.connected
      ? 'None'
      : '—';
  const disabled = !ready || busy;
  return (
    <>
      <header className="session-header" aria-label="Reader session">
        <div className="reader-field">
          <label htmlFor="reader">Reader</label>
          <select
            id="reader"
            value={reader}
            onChange={(event) => setReader(event.target.value)}
            disabled={disabled}
          >
            <option value="">
              {!readers.length ? (ready ? 'No readers' : 'Reader unavailable') : 'Choose reader'}
            </option>
            {readers.map((item) => (
              <option key={item.name} value={item.name}>
                {item.name}
                {item.card_present ? '' : ' · empty'}
              </option>
            ))}
          </select>
        </div>
        <div className="reader-actions">
          <button className="button" onClick={() => send('list_readers')} disabled={disabled}>
            Scan
          </button>
          <button
            className="button primary"
            onClick={() => send('connect', { reader, wait_ms: '0' })}
            disabled={disabled || !reader || session?.requires_restart}
          >
            {session?.connected || reconnect ? 'Reconnect' : 'Connect'}
          </button>
          <button
            className="button"
            onClick={() => send('disconnect')}
            disabled={disabled || !session?.connected}
          >
            Disconnect
          </button>
        </div>
        <div className="session-badge">
          <span
            className={`connection-dot ${reconnect ? 'warning' : session?.connected ? 'connected' : ''}`}
          />
          <span role="status">{busy ? 'Working…' : sessionStatus(session, ready, uncertain)}</span>
          <button
            className="icon-button"
            onClick={() => send('status')}
            disabled={disabled}
            aria-label="Refresh session status"
            title="Refresh session status"
          >
            ↻
          </button>
        </div>
      </header>
      <div className="session-context">
        <span>
          AID <strong className="mono">{session?.selected_aid ?? '—'}</strong>
        </span>
        <span>
          Auth <strong>{authLabel}</strong>
        </span>
        <span className="atr-context" title={session?.atr ?? ''}>
          ATR <strong className="mono">{session?.atr || '—'}</strong>
        </span>
      </div>
    </>
  );
}
