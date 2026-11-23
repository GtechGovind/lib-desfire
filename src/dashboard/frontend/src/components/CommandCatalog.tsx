import type { Ref } from 'react';
import { label } from '../presentation.ts';
import type { Command } from '../types.ts';

type Props = {
  commands: Command[];
  selected?: string;
  query: string;
  group: string;
  ready: boolean;
  disabled: boolean;
  searchRef: Ref<HTMLInputElement>;
  setQuery: (query: string) => void;
  setGroup: (group: string) => void;
  choose: (name: string) => void;
};

export function CommandCatalog({
  commands,
  selected,
  query,
  group,
  ready,
  disabled,
  searchRef,
  setQuery,
  setGroup,
  choose,
}: Props) {
  const groups = [...new Set(commands.map((command) => command.group))];
  const visible = commands.filter(
    (command) =>
      (!group || command.group === group) &&
      `${command.label} ${command.name} ${command.group}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const visibleGroups = [...new Set(visible.map((command) => command.group))];
  return (
    <aside className="catalog panel" aria-label="Command catalog">
      <div className="catalog-tools">
        <input
          ref={searchRef}
          type="search"
          placeholder="Find command"
          aria-label="Find command"
          autoComplete="off"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <select
          aria-label="Command group"
          value={group}
          onChange={(event) => setGroup(event.target.value)}
        >
          <option value="">All groups</option>
          {groups.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
      </div>
      <div className="command-list">
        {visibleGroups.map((name) => (
          <div className="command-section" key={name}>
            <div className="command-group">{name}</div>
            {visible
              .filter((command) => command.group === name)
              .map((command) => (
                <button
                  className={`command-item ${command.name === selected ? 'selected' : ''}`}
                  key={command.name}
                  aria-pressed={command.name === selected}
                  disabled={disabled}
                  onClick={() => choose(command.name)}
                >
                  {label(command.label)}
                  {command.mutating && <span className="mutation-mark" aria-label="Changes card" />}
                </button>
              ))}
          </div>
        ))}
        {!visible.length && <div className="empty-cell">{ready ? 'No commands' : 'Loading…'}</div>}
      </div>
      <div className="catalog-footer">
        {visible.length} / {commands.length} commands
      </div>
    </aside>
  );
}
