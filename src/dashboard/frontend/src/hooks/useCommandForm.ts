import { useState } from 'react';
import { commandView } from '../presentation.ts';
import { clearSensitiveArgs } from '../privacy.ts';
import type { Args, Command, Credential, View } from '../types.ts';
import { defaults } from '../validation.ts';

const preferredCommands: Record<Exclude<View, 'activity'>, string> = {
  native: 'get_version',
  iso7816: 'iso7816_select_master_file',
  raw: 'raw_apdu',
  keys: 'credential_add',
};

export function useCommandForm(commands: Command[], credentials: Credential[], busy: boolean) {
  const [view, setView] = useState<View>('native');
  const [selection, setSelection] = useState<{ name: string; values: Args | null }>({
    name: 'get_version',
    values: null,
  });
  const [query, setQuery] = useState('');
  const [group, setGroup] = useState('');
  const command =
    commands.find((item) => item.name === selection.name) ??
    commands.find((item) => item.protocol === 'native');
  const args = selection.values ?? (command ? defaults(command) : {});

  function clearSecrets() {
    if (command) {
      setSelection({ name: command.name, values: clearSensitiveArgs(command, args) });
    }
  }

  function choose(name: string, values: Args = {}) {
    if (busy) {
      return;
    }
    const target = commands.find((item) => item.name === name);
    if (!target) {
      return;
    }
    setSelection({ name, values: { ...defaults(target), ...values } });
    setView(commandView(target));
  }

  function navigate(next: View) {
    if (busy) {
      return;
    }
    clearSecrets();
    setView(next);
    setQuery('');
    setGroup('');
    if (next !== 'activity' && (!command || commandView(command) !== next)) {
      choose(preferredCommands[next]);
    }
  }

  function changeField(name: string, value: string) {
    if (!command || busy) {
      return;
    }
    let values = { ...args, [name]: value };
    if (name === 'credential_id' && command.name !== 'credential_remove') {
      const saved = credentials.find((item) => item.id === value);
      values = {
        ...values,
        key: '',
        ...(saved
          ? {
              number: String(saved.number),
              ...(command.fields.some((field) => field.name === 'key_type')
                ? { key_type: saved.key_type }
                : {}),
            }
          : {}),
      };
    }
    setSelection({ name: command.name, values });
  }

  function useCredential(saved: Credential) {
    setQuery('');
    setGroup('');
    const name =
      saved.key_type === 'aes_128'
        ? 'authenticate_aes'
        : saved.key_type === 'tdes_3k'
          ? 'authenticate_iso'
          : 'authenticate';
    choose(name, {
      credential_id: saved.id,
      number: String(saved.number),
      key_type: saved.key_type,
      key: '',
    });
  }

  return {
    view,
    command,
    args,
    query,
    setQuery,
    group,
    setGroup,
    choose,
    navigate,
    changeField,
    clearSecrets,
    useCredential,
  };
}
