import { errorMessage, responseMeta } from '../presentation.ts';
import type { Activity } from '../types.ts';

type Props = { entries: Activity[]; disabled: boolean; select: (entry: Activity) => void };

export function ActivityTable({ entries, disabled, select }: Props) {
  return (
    <section className="activity-panel panel" aria-label="Session activity">
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Command</th>
              <th>Result</th>
              <th>Status / delivery</th>
              <th>Duration</th>
            </tr>
          </thead>
          <tbody>
            {entries.length ? (
              entries.map((entry) => (
                <tr
                  key={entry.id}
                  className="activity-row"
                  tabIndex={disabled ? -1 : 0}
                  role="button"
                  aria-disabled={disabled}
                  aria-label={`${entry.label}, ${entry.response.ok ? 'OK' : 'Error'}, ${entry.time}`}
                  onClick={() => {
                    if (!disabled) {
                      select(entry);
                    }
                  }}
                  onKeyDown={(event) => {
                    if (!disabled && (event.key === 'Enter' || event.key === ' ')) {
                      event.preventDefault();
                      select(entry);
                    }
                  }}
                >
                  <td className="mono">{entry.time}</td>
                  <td>
                    <strong>{entry.label}</strong>
                  </td>
                  <td className={entry.response.ok ? 'ok' : 'error'}>
                    {entry.response.ok ? 'OK' : 'Error'}
                  </td>
                  <td
                    className="mono"
                    title={entry.response.ok ? '' : errorMessage(entry.response.error)}
                  >
                    {responseMeta(entry.response)
                      .map(([name, value]) => `${name} ${value}`)
                      .join(' · ') ||
                      (entry.response.ok ? '—' : errorMessage(entry.response.error))}
                  </td>
                  <td className="mono">{entry.duration} ms</td>
                </tr>
              ))
            ) : (
              <tr>
                <td className="empty-cell" colSpan={5}>
                  No activity.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
