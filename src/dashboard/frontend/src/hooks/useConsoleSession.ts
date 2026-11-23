import { useCallback, useEffect, useRef, useState } from 'react';
import { executeCommand, loadBootstrap } from '../api/client.ts';
import { commandBlockReason, errorMessage, label } from '../presentation.ts';
import { commandSecrets } from '../privacy.ts';
import type {
  Activity,
  ApiResponse,
  Args,
  Command,
  Credential,
  Reader,
  Session,
} from '../types.ts';
import { normalizeArgs, validateArgs } from '../validation.ts';

const activityLimit = 500;
type Connection = {
  token: string;
  commands: Command[];
  session: Session | null;
  credentials: Credential[];
  uncertain: boolean;
};

export function useConsoleSession() {
  const [commands, setCommands] = useState<Command[]>([]);
  const [session, setSession] = useState<Session | null>(null);
  const [readers, setReaders] = useState<Reader[]>([]);
  const [reader, setReader] = useState('');
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [notice, setNotice] = useState('');
  const [entries, setEntries] = useState<Activity[]>([]);
  const [result, setResult] = useState<Activity | null>(null);
  const connection = useRef<Connection>({
    token: '',
    commands: [],
    session: null,
    credentials: [],
    uncertain: false,
  });
  const inFlight = useRef(false);
  const mounted = useRef(false);
  const nextId = useRef(0);

  const run = useCallback(
    async (
      name: string,
      input: Args = {},
      confirm = false,
      reviewedRevision?: string,
    ): Promise<void> => {
      const current = connection.current;
      if (inFlight.current || !current.token || !mounted.current) {
        return;
      }
      const command = current.commands.find((item) => item.name === name);
      if (!command) {
        setNotice('Command unavailable.');
        return;
      }
      const blocked = commandBlockReason(command, current.session, current.uncertain);
      const errors = validateArgs(
        command,
        input,
        current.credentials,
        current.session?.selected_aid ?? null,
      );
      if (blocked || Object.keys(errors).length) {
        setNotice(blocked || Object.values(errors)[0]);
        return;
      }
      if ((command.mutating || command.protocol === 'raw') && !confirm) {
        setNotice('Review this command before sending.');
        return;
      }

      // This synchronous lock covers every control, including events before React renders busy state.
      inFlight.current = true;
      setBusy(true);
      setNotice('');
      const start = performance.now();
      const args = normalizeArgs(command, input);
      const secrets = commandSecrets(command, args);
      // Recovery deliberately omits a revision: a lost reply may have advanced the server.
      const expectedRevision =
        command.protocol !== 'system'
          ? (reviewedRevision ?? current.session?.session_revision)
          : undefined;
      const changesCardSession =
        command.protocol !== 'system' || name === 'connect' || name === 'disconnect';
      let response: ApiResponse;
      try {
        response = await executeCommand(
          current.token,
          { command: name, args, confirm, expected_revision: expectedRevision },
          secrets,
        );
      } catch {
        // Once card traffic is submitted, a lost/malformed HTTP reply cannot establish delivery.
        response = {
          ok: false,
          error: {
            message: changesCardSession
              ? 'Connection lost. Delivery unknown. Reconnect required.'
              : 'Console request failed.',
            delivery: changesCardSession ? 'unknown' : 'unavailable',
          },
        };
      }
      if (!mounted.current) {
        inFlight.current = false;
        return;
      }

      if (response.state) {
        current.session = response.state;
        setSession(response.state);
      }
      if (response.result?.readers) {
        const actualReaders = response.result.readers;
        setReaders(actualReaders);
        setReader((previous) =>
          actualReaders.some((item) => item.name === previous)
            ? previous
            : (actualReaders.find((item) => item.name === current.session?.reader)?.name ?? ''),
        );
      }
      if (response.result?.credentials) {
        current.credentials = response.result.credentials;
        setCredentials(current.credentials);
      }
      if (
        name === 'connect' &&
        response.ok &&
        response.state?.connected &&
        !response.state.requires_reconnect &&
        !response.state.requires_restart
      ) {
        current.uncertain = false;
      }
      const delivery = response.error?.delivery ?? response.result?.delivery;
      if (
        delivery === 'unknown' ||
        (changesCardSession && !response.state && delivery !== 'not_sent')
      ) {
        current.uncertain = true;
      }
      setUncertain(current.uncertain);
      if (!response.ok) {
        setNotice(errorMessage(response.error));
      }
      const activity: Activity = {
        id: ++nextId.current,
        time: new Date().toLocaleTimeString([], { hour12: false }),
        command: name,
        label: label(command.label),
        duration: Math.round(performance.now() - start),
        response,
      };
      setResult(activity);
      setEntries((previous) => [activity, ...previous].slice(0, activityLimit));
      inFlight.current = false;
      setBusy(false);
    },
    [],
  );

  useEffect(() => {
    const controller = new AbortController();
    mounted.current = true;
    async function start() {
      try {
        const bootstrap = await loadBootstrap(controller.signal);
        if (controller.signal.aborted) {
          return;
        }
        connection.current = {
          token: bootstrap.token,
          commands: bootstrap.commands,
          session: bootstrap.state,
          credentials: bootstrap.credentials,
          uncertain: false,
        };
        setCommands(bootstrap.commands);
        setSession(bootstrap.state);
        setCredentials(bootstrap.credentials);
        setReady(true);
        if (bootstrap.error) {
          setNotice(errorMessage(bootstrap.error));
        }
        // Enumeration is the only automatic command; connection and card commands are explicit.
        await run('list_readers');
      } catch (error) {
        if (!controller.signal.aborted) {
          setNotice(error instanceof Error ? error.message : 'Console unavailable.');
        }
      }
    }
    void start();
    return () => {
      mounted.current = false;
      controller.abort();
      connection.current.token = '';
    };
  }, [run]);

  return {
    commands,
    session,
    readers,
    reader,
    setReader,
    credentials,
    ready,
    busy,
    uncertain,
    notice,
    entries,
    result,
    selectResult: setResult,
    clearActivity: () => {
      setEntries([]);
      setResult(null);
    },
    run,
  };
}
