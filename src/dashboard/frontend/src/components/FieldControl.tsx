import type { ChangeEvent } from 'react';
import { keyType, label } from '../presentation.ts';
import { isSensitiveField } from '../privacy.ts';
import type { Args, Command, Credential, Field, Session } from '../types.ts';
import { hex } from '../validation.ts';

type Props = {
  field: Field;
  value: string;
  error?: string;
  command: Command;
  args: Args;
  credentials: Credential[];
  session: Session | null;
  disabled: boolean;
  canSelectAid: boolean;
  onChange: (name: string, value: string) => void;
  selectAid: (aid: string) => void;
};

export function FieldControl({
  field,
  value,
  error,
  command,
  args,
  credentials,
  session,
  disabled,
  canSelectAid,
  onChange,
  selectAid,
}: Props) {
  const savedField = field.name === 'credential_id';
  const saved = credentials.find((item) => item.id === args.credential_id);
  const sensitive = isSensitiveField(command, field);
  const wide = savedField || (field.type === 'hex' && !field.width && !field.secret);
  const id = `field-${command.name}-${field.name}`;
  const common = {
    id,
    name: field.name,
    value,
    disabled: disabled || (Boolean(saved) && ['key', 'number', 'key_type'].includes(field.name)),
    'aria-invalid': Boolean(error),
    'aria-describedby': error ? `${id}-error` : undefined,
    onChange: (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
      onChange(field.name, event.target.value),
  };
  let control;
  if (savedField) {
    control = (
      <select {...common}>
        <option value="">
          {command.name === 'credential_remove' ? 'Choose key' : 'Enter key below'}
        </option>
        {credentials.map((item) => (
          <option key={item.id} value={item.id}>
            {item.name} · {hex(item.aid)} · {item.number} · {keyType(item.key_type)}
          </option>
        ))}
      </select>
    );
  } else if (field.type === 'select') {
    control = (
      <select {...common}>
        {field.options?.map((option) => (
          <option key={option} value={option}>
            {field.name.includes('type') ? keyType(option) : option.replaceAll('_', ' ')}
          </option>
        ))}
      </select>
    );
  } else if (wide && !sensitive) {
    control = (
      <textarea
        {...common}
        className="mono"
        spellCheck={false}
        autoComplete="off"
        placeholder="00 01 02…"
      />
    );
  } else {
    control = (
      <input
        {...common}
        type={sensitive ? 'password' : 'text'}
        inputMode={field.type === 'number' ? 'numeric' : 'text'}
        className={field.type !== 'text' ? 'mono' : undefined}
        spellCheck={false}
        autoComplete={sensitive ? 'new-password' : 'off'}
        placeholder={
          field.type === 'hex'
            ? field.width
              ? '00'.repeat(field.width / 2)
              : 'Hex bytes'
            : undefined
        }
      />
    );
  }
  return (
    <div className={`field ${wide ? 'wide' : ''}`}>
      <label className="field-label" htmlFor={id}>
        {label(field.label)}
        <small>
          {sensitive ? (
            'SECRET'
          ) : field.type === 'hex' ? (
            <span className="hex-label">{field.width ? `${field.width / 2} B · HEX` : 'HEX'}</span>
          ) : field.required === false ? (
            'optional'
          ) : (
            ''
          )}
        </small>
      </label>
      {control}
      {error && (
        <span className="field-error" id={`${id}-error`}>
          {error}
        </span>
      )}
      {savedField && saved && command.name !== 'credential_remove' && (
        <div className="credential-info">
          <span>
            AID <span className="mono">{hex(saved.aid)}</span> · {keyType(saved.key_type)} · Key{' '}
            {saved.number}
          </span>
          {hex(saved.aid) !== hex(session?.selected_aid ?? '') && (
            <button
              className="link-button"
              type="button"
              disabled={disabled || !canSelectAid}
              onClick={() => selectAid(saved.aid)}
            >
              Select AID {hex(saved.aid)}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
