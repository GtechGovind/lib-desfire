import { sessionStatus, views } from '../presentation.ts';
import type { Command, Session, View } from '../types.ts';

type Props = {
  view: View;
  commands: Command[];
  activityCount: number;
  session: Session | null;
  ready: boolean;
  busy: boolean;
  uncertain: boolean;
  navigate: (view: View) => void;
};

export function Sidebar({
  view,
  commands,
  activityCount,
  session,
  ready,
  busy,
  uncertain,
  navigate,
}: Props) {
  const warning = uncertain || session?.requires_reconnect;
  return (
    <aside className="sidebar">
      <a
        className="brand"
        href="#native"
        aria-label="DESFire card console"
        onClick={(event) => {
          event.preventDefault();
          navigate('native');
        }}
      >
        <span className="brand-mark" aria-hidden="true">
          D<span>F</span>
        </span>
        <span>
          DESFire<small>CARD CONSOLE</small>
        </span>
      </a>
      <nav aria-label="Workspace">
        {views.map(({ name, title, icon }) => (
          <button
            key={name}
            className={`nav-button ${view === name ? 'active' : ''}`}
            aria-current={view === name ? 'page' : undefined}
            disabled={busy}
            onClick={() => navigate(name)}
          >
            <span aria-hidden="true" className={name === 'raw' ? 'nav-code' : ''}>
              {icon}
            </span>
            {title}
            {['native', 'iso7816', 'activity'].includes(name) && (
              <span className="nav-count">
                {name === 'activity'
                  ? activityCount
                  : commands.filter((item) => item.protocol === name).length || ''}
              </span>
            )}
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        <span
          className={`connection-dot ${warning ? 'warning' : session?.connected ? 'connected' : ''}`}
        />
        <span>{sessionStatus(session, ready, uncertain)}</span>
        <span className="mono">PC/SC</span>
      </div>
    </aside>
  );
}
