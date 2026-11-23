import { responseMeta } from '../presentation.ts';
import { publicJson } from '../privacy.ts';
import type { Activity } from '../types.ts';
import { hex } from '../validation.ts';

type Props = { activity: Activity | null; copy: () => void };

export function ResultPanel({ activity, copy }: Props) {
  const response = activity?.response;
  const meta = response ? responseMeta(response) : [];
  const data = response?.result?.data;
  const responseHex =
    data && /^(?:[0-9a-fA-F]{2}\s*)+$/.test(data)
      ? hex(data)
          .match(/.{1,2}/g)
          ?.join(' ')
      : null;
  return (
    <section className="result panel" aria-label="Command response">
      <div className="result-heading">
        <h2>{activity ? `${activity.label} response` : 'Response'}</h2>
        <span
          role="status"
          className={`result-state ${response ? (response.ok ? 'ok' : 'error') : ''}`}
        >
          {response ? (response.ok ? 'OK' : 'Error') : '—'}
        </span>
        <span className="result-time">{activity ? `${activity.duration} ms` : ''}</span>
        <button className="button small" disabled={!response} onClick={copy}>
          Copy
        </button>
      </div>
      {meta.length > 0 && (
        <div className="response-meta">
          {meta.map(([name, value]) => (
            <span key={name}>
              {name}
              <strong>{value}</strong>
            </span>
          ))}
        </div>
      )}
      {responseHex && (
        <div className="response-hex">
          <span>HEX</span>
          <pre tabIndex={0}>{responseHex}</pre>
        </div>
      )}
      <pre className="json-output" tabIndex={0}>
        {response ? publicJson(response) : 'No response.'}
      </pre>
    </section>
  );
}
