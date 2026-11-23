import type { Ref, SubmitEvent } from 'react';
import { label } from '../presentation.ts';
import type { Args, Command, Credential, Session } from '../types.ts';
import { FieldControl } from './FieldControl.tsx';

type Props = {
  command?: Command;
  args: Args;
  errors: Record<string, string>;
  credentials: Credential[];
  session: Session | null;
  ready: boolean;
  busy: boolean;
  blockReason: string;
  canSelectAid: boolean;
  formRef: Ref<HTMLFormElement>;
  changeField: (name: string, value: string) => void;
  selectAid: (aid: string) => void;
  submit: (event: SubmitEvent<HTMLFormElement>) => void;
};

export function CommandEditor({
  command,
  args,
  errors,
  credentials,
  session,
  ready,
  busy,
  blockReason,
  canSelectAid,
  formRef,
  changeField,
  selectAid,
  submit,
}: Props) {
  const firstError = Object.values(errors)[0];
  const status = !ready
    ? 'Console unavailable'
    : busy
      ? 'Working…'
      : blockReason ||
        firstError ||
        (command?.mutating
          ? 'Review before sending'
          : command?.name === 'iso7816_authenticate'
            ? '84 · 82 · 88'
            : '');
  const protocolLabel =
    command?.protocol === 'iso7816'
      ? 'ISO 7816'
      : command?.protocol === 'native'
        ? 'Native'
        : command?.protocol === 'raw'
          ? 'Raw'
          : 'Local';
  return (
    <section className="editor panel" aria-labelledby="command-title">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">{command?.group ?? 'COMMAND'}</span>
          <h2 id="command-title">
            {command ? label(command.label) : ready ? 'No command' : 'Console unavailable'}
          </h2>
        </div>
        {command && (
          <span className={`tag ${command.mutating ? 'write' : ''}`}>
            {protocolLabel}
            {command.mutating ? ' · Write' : ''}
          </span>
        )}
      </div>
      <form ref={formRef} onSubmit={submit} noValidate autoComplete="off">
        <div className="field-grid">
          {command?.fields.map((field) => (
            <FieldControl
              key={`${command.name}-${field.name}`}
              field={field}
              value={args[field.name] ?? ''}
              error={errors[field.name]}
              command={command}
              args={args}
              credentials={credentials}
              session={session}
              disabled={busy}
              canSelectAid={canSelectAid}
              onChange={changeField}
              selectAid={selectAid}
            />
          ))}
          {command && !command.fields.length && <span className="no-fields">No parameters.</span>}
        </div>
        <div className="form-footer">
          <span
            className={`form-status ${firstError && !blockReason ? 'invalid' : ''}`}
            aria-live="polite"
          >
            {status}
          </span>
          <button
            className="button primary"
            type="submit"
            disabled={!command || !ready || busy || Boolean(blockReason) || Boolean(firstError)}
          >
            {busy
              ? 'Working…'
              : command?.mutating || command?.protocol === 'raw'
                ? 'Review command'
                : command?.name === 'credential_add'
                  ? 'Save key'
                  : 'Run command'}
            <span aria-hidden="true">↗</span>
          </button>
        </div>
      </form>
    </section>
  );
}
