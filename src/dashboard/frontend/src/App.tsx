import { useRef, useState } from 'react';
import type { SubmitEvent } from 'react';
import { exportActivity } from './activity.ts';
import { ActivityTable } from './components/ActivityTable.tsx';
import { CommandCatalog } from './components/CommandCatalog.tsx';
import { CommandEditor } from './components/CommandEditor.tsx';
import { KeyTable } from './components/KeyTable.tsx';
import { ResultPanel } from './components/ResultPanel.tsx';
import { ReviewDialog } from './components/ReviewDialog.tsx';
import type { PendingCommand } from './components/ReviewDialog.tsx';
import { SessionHeader } from './components/SessionHeader.tsx';
import { Sidebar } from './components/Sidebar.tsx';
import { useCommandForm } from './hooks/useCommandForm.ts';
import { useConsoleSession } from './hooks/useConsoleSession.ts';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts.ts';
import { useToast } from './hooks/useToast.ts';
import { commandBlockReason, sessionStatus, views } from './presentation.ts';
import { publicJson } from './privacy.ts';
import type { Args } from './types.ts';
import { normalizeArgs, validateArgs } from './validation.ts';

export default function App() {
  const consoleSession = useConsoleSession();
  const { commands, session, credentials, ready, busy, uncertain, notice, entries, run } =
    consoleSession;
  const form = useCommandForm(commands, credentials, busy);
  const { view, command, args } = form;
  const { toast, notify } = useToast();
  const [review, setReview] = useState<PendingCommand | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  useKeyboardShortcuts(!review && view !== 'activity' && !busy, searchRef, formRef);

  const relevant = commands.filter((item) =>
    view === 'keys' ? item.name.startsWith('credential_') : item.protocol === view,
  );
  const errors = command
    ? validateArgs(command, args, credentials, session?.selected_aid ?? null)
    : {};
  const blockReason = command ? commandBlockReason(command, session, uncertain) : '';
  const selectCommand = commands.find((item) => item.name === 'select_application');
  const canSelectAid = Boolean(
    selectCommand && !commandBlockReason(selectCommand, session, uncertain),
  );
  const displayedResult =
    view === 'activity' || consoleSession.result?.command === command?.name
      ? consoleSession.result
      : null;
  const status = sessionStatus(session, ready, uncertain);

  function send(name: string, values: Args = {}) {
    form.clearSecrets();
    void run(name, values);
  }

  function submit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!command || busy || !ready || blockReason || Object.keys(errors).length || review) {
      return;
    }
    const values = normalizeArgs(command, args);
    // Secret inputs live only until use; review temporarily owns its pending request.
    form.clearSecrets();
    if (command.mutating || command.protocol === 'raw') {
      if (session) {
        setReview({ command, args: values, expectedRevision: session.session_revision });
      }
    } else {
      void run(command.name, values);
    }
  }

  function confirmReview() {
    if (!review) {
      return;
    }
    const pending = review;
    setReview(null);
    void run(pending.command.name, pending.args, true, pending.expectedRevision);
  }

  async function copyResponse() {
    if (!displayedResult) {
      return;
    }
    try {
      await navigator.clipboard.writeText(publicJson(displayedResult.response));
      notify('Copied');
    } catch {
      notify('Clipboard unavailable');
    }
  }

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to commands
      </a>
      <Sidebar
        view={view}
        commands={commands}
        activityCount={entries.length}
        session={session}
        ready={ready}
        busy={busy}
        uncertain={uncertain}
        navigate={form.navigate}
      />
      <div className="workspace">
        <SessionHeader
          session={session}
          readers={consoleSession.readers}
          reader={consoleSession.reader}
          setReader={consoleSession.setReader}
          busy={busy}
          ready={ready}
          uncertain={uncertain}
          send={send}
        />
        <main id="main" tabIndex={-1}>
          {notice && (
            <div className="notice" role="alert">
              {notice}
            </div>
          )}
          {(session?.requires_reconnect || session?.requires_restart || uncertain) && (
            <div className="notice warning" role="status">
              {session?.requires_restart
                ? 'Restart console required.'
                : uncertain
                  ? 'Session state uncertain. Reconnect required.'
                  : 'Typed commands require reconnect.'}
            </div>
          )}
          <div className="page-heading">
            <h1>{views.find((item) => item.name === view)?.title}</h1>
            <span className="page-meta">
              {view === 'activity'
                ? `${entries.length} events`
                : view === 'keys'
                  ? `${credentials.length} saved`
                  : `${relevant.length} commands`}
            </span>
            {view === 'keys' && (
              <div className="page-actions">
                <button
                  className="button"
                  disabled={!ready || busy}
                  onClick={() => send('credential_list')}
                >
                  Refresh
                </button>
                <button
                  className="button primary"
                  disabled={!ready || busy}
                  onClick={() => form.choose('credential_add')}
                >
                  Add key
                </button>
              </div>
            )}
            {view === 'activity' && (
              <div className="page-actions">
                <button
                  className="button"
                  disabled={!entries.length || busy}
                  onClick={() => exportActivity(entries)}
                >
                  Export
                </button>
                <button
                  className="button"
                  disabled={!entries.length || busy}
                  onClick={consoleSession.clearActivity}
                >
                  Clear
                </button>
              </div>
            )}
          </div>
          {view === 'keys' && (
            <KeyTable
              credentials={credentials}
              disabled={!ready || busy}
              onUseKey={form.useCredential}
              removeKey={(saved) => send('credential_remove', { credential_id: saved.id })}
            />
          )}
          {view === 'activity' ? (
            <div className="workbench">
              <ActivityTable
                entries={entries}
                disabled={busy}
                select={consoleSession.selectResult}
              />
              <ResultPanel activity={displayedResult} copy={() => void copyResponse()} />
            </div>
          ) : (
            <section className="command-layout" aria-label="Command workbench">
              <CommandCatalog
                commands={relevant}
                selected={command?.name}
                query={form.query}
                group={form.group}
                ready={ready}
                disabled={busy}
                searchRef={searchRef}
                setQuery={form.setQuery}
                setGroup={form.setGroup}
                choose={form.choose}
              />
              <div className="workbench">
                <CommandEditor
                  command={command}
                  args={args}
                  errors={errors}
                  credentials={credentials}
                  session={session}
                  ready={ready}
                  busy={busy}
                  blockReason={blockReason}
                  canSelectAid={canSelectAid}
                  formRef={formRef}
                  changeField={form.changeField}
                  selectAid={(aid) => send('select_application', { aid })}
                  submit={submit}
                />
                <ResultPanel activity={displayedResult} copy={() => void copyResponse()} />
              </div>
            </section>
          )}
        </main>
        <footer>
          <span>
            {ready
              ? busy
                ? 'Working…'
                : `${commands.length} commands · ${status}`
              : 'Console unavailable'}
          </span>
          <span className="shortcut">/ Search · Ctrl Enter Run</span>
        </footer>
      </div>
      {review && (
        <ReviewDialog
          {...review}
          session={session}
          onCancel={() => {
            setReview(null);
            form.clearSecrets();
          }}
          onConfirm={confirmReview}
        />
      )}
      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </>
  );
}
