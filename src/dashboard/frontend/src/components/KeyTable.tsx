import { keyType } from '../presentation.ts';
import type { Credential } from '../types.ts';
import { hex } from '../validation.ts';

type Props = {
  credentials: Credential[];
  disabled: boolean;
  onUseKey: (key: Credential) => void;
  removeKey: (key: Credential) => void;
};

export function KeyTable({ credentials, disabled, onUseKey, removeKey }: Props) {
  return (
    <section className="keys-panel panel" aria-label="Saved keys">
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>AID</th>
              <th>Key</th>
              <th>Type</th>
              <th>Version</th>
              <th>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {credentials.length ? (
              credentials.map((item) => (
                <tr key={item.id}>
                  <td>
                    <strong>{item.name}</strong>
                  </td>
                  <td className="mono">{hex(item.aid)}</td>
                  <td className="mono">{item.number}</td>
                  <td>{keyType(item.key_type)}</td>
                  <td className="mono">{item.version}</td>
                  <td>
                    <div className="table-actions">
                      <button
                        className="link-button"
                        disabled={disabled}
                        onClick={() => onUseKey(item)}
                        aria-label={`Use ${item.name}`}
                      >
                        Use
                      </button>
                      <button
                        className="link-button remove"
                        disabled={disabled}
                        onClick={() => removeKey(item)}
                        aria-label={`Remove ${item.name}`}
                      >
                        Remove
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td className="empty-cell" colSpan={6}>
                  No saved keys.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
