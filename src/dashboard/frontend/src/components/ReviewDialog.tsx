import { useEffect, useRef } from 'react';
import { label } from '../presentation.ts';
import { isSensitiveField } from '../privacy.ts';
import type { Args, Command, Session } from '../types.ts';

export type PendingCommand = { command: Command; args: Args; expectedRevision: string };
type Props = PendingCommand & {
  session: Session | null;
  onCancel: () => void;
  onConfirm: () => void;
};

export function ReviewDialog({ command, args, session, onCancel, onConfirm }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  return (
    <dialog
      ref={dialog}
      aria-labelledby="review-title"
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          onConfirm();
        }}
      >
        <div className="dialog-heading">
          <span className="eyebrow">REVIEW</span>
          <h2 id="review-title">{label(command.label)}</h2>
        </div>
        <p className="review-context">
          {session?.reader ?? 'No reader'} · AID {session?.selected_aid ?? '—'}
        </p>
        <dl className="review-fields">
          {command.fields.map((field) => (
            <div key={field.name}>
              <dt>{label(field.label)}</dt>
              <dd>{isSensitiveField(command, field) ? '••••••••' : args[field.name] || '—'}</dd>
            </div>
          ))}
        </dl>
        <p className="review-warning">
          {command.protocol === 'raw'
            ? 'Typed commands require reconnect after raw traffic.'
            : 'This command changes the card.'}
        </p>
        <div className="dialog-footer">
          <button className="button" type="button" onClick={onCancel}>
            Cancel
          </button>
          <button className="button primary" type="submit" autoFocus>
            Send command
          </button>
        </div>
      </form>
    </dialog>
  );
}
