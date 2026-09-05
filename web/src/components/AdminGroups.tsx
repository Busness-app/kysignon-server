import React, { useCallback, useEffect, useRef, useState } from 'react';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseGroupPage, parseGroupUserPage } from '../parsers';
import type { DirectoryGroup, DirectoryPage, User } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';

const pageSize = 25;
function useDirectoryPage<T>(url: string, parse: (value: unknown) => DirectoryPage<T>) {
  const [page, setPage] = useState<DirectoryPage<T> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision(value => value + 1), []);
  useEffect(() => {
    const controller = new AbortController();
    setPage(null);
    setError(null);
    void apiJson(url, parse, { signal: controller.signal }).then(value => {
      if (!controller.signal.aborted) setPage(value);
    }).catch(err => {
      if (!controller.signal.aborted) setError(errorMessage(err, 'Could not load directory'));
    });
    return () => controller.abort();
  }, [url, parse, revision]);
  return { page, error, reload };
}

function Pager({ page, offset, onChange }: {
  page: DirectoryPage<unknown> | null; offset: number; onChange: (offset: number) => void;
}) {
  return <div className="pagination-bar">
    <span className="pagination-info">{page ? `${page.total} total · Page ${Math.floor(offset / pageSize) + 1}` : 'Loading...'}</span>
    <div className="pagination-nav">
      <button className="pagination-page-btn" disabled={!page || offset === 0} onClick={() => onChange(Math.max(0, offset - pageSize))}>Previous</button>
      <button className="pagination-page-btn" disabled={!page || offset + pageSize >= page.total} onClick={() => onChange(offset + pageSize)}>Next</button>
    </div>
  </div>;
}

type Mutate = (reason: string, method: 'POST' | 'PUT' | 'DELETE', path: string, body?: { name: string; description: string }) => Promise<boolean>;

function GroupMembers({ group, busy, mutate, onClose }: {
  group: DirectoryGroup; busy: boolean; mutate: Mutate; onClose: () => void;
}) {
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [includeNonMembers, setIncludeNonMembers] = useState(false);
  const heading = useRef<HTMLHeadingElement | null>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  const params = new URLSearchParams({ q: query, offset: String(offset), limit: String(pageSize), includeNonMembers: String(includeNonMembers) });
  const { page, error, reload } = useDirectoryPage(`/api/admin/groups/${group.id}/members?${params}`, parseGroupUserPage);
  useEffect(() => { if (page && offset > 0 && offset >= page.total) setOffset(Math.max(0, offset - pageSize)); }, [page, offset]);
  return <section className="settings-section" aria-labelledby="group-members-title">
    <div className="section-header">
      <h2 id="group-members-title" ref={heading} tabIndex={-1}>Members of {group.name}</h2>
      <button className="secondary-btn" disabled={busy} onClick={onClose}>Back to groups</button>
    </div>
    <div className="form-group">
      <label className="form-label" htmlFor="group-member-search">Search users by name or email</label>
      <input id="group-member-search" className="form-input" maxLength={200} value={query} disabled={busy}
        onChange={e => { setQuery(e.target.value); setOffset(0); }} />
    </div>
    <div className="form-group"><label><input type="checkbox" checked={includeNonMembers} disabled={busy}
      onChange={e => { setIncludeNonMembers(e.target.checked); setOffset(0); }} /> Include users available to add</label></div>
    {error && <div className="alert-box error" role="alert">{error}<button className="secondary-btn sm" onClick={reload}>Retry</button></div>}
    <div className="table-card"><table className="admin-table">
      <thead><tr><th>User</th><th>Email</th><th>Status</th><th>Membership</th></tr></thead>
      <tbody>{page?.items.map(user => <tr key={user.id}>
        <td>{user.displayName || user.username}<div className="text-muted text-sm">{user.username}</div></td>
        <td>{user.email}</td><td>{user.status}</td>
        <td><button className="secondary-btn sm" disabled={busy} onClick={async () => {
          if (await mutate(`${user.member ? 'Remove' : 'Add'} '${user.username}' ${user.member ? 'from' : 'to'} '${group.name}'.`,
            user.member ? 'DELETE' : 'PUT', `/api/admin/groups/${group.id}/members/${user.id}`)) reload();
        }}>{user.member ? 'Remove member' : 'Add member'}</button></td>
      </tr>)}</tbody>
    </table></div>
    {page?.items.length === 0 && <p className="empty-box">No matching users. Include users available to add to find new members.</p>}
    <Pager page={page} offset={offset} onChange={setOffset} />
  </section>;
}

export function AdminGroups({ user, onClearUser }: { user: User | null; onClearUser: () => void }) {
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [editor, setEditor] = useState<{ kind: 'new' } | { kind: 'edit'; group: DirectoryGroup } | null>(null);
  const [selected, setSelected] = useState<DirectoryGroup | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const params = new URLSearchParams({ q: query, offset: String(offset), limit: String(pageSize) });
  if (user) params.set('userId', user.id);
  const { page, error, reload } = useDirectoryPage(`/api/admin/groups?${params}`, parseGroupPage);
  useEffect(() => { if (page && offset > 0 && offset >= page.total) setOffset(Math.max(0, offset - pageSize)); }, [page, offset]);
  const mutate: Mutate = async (reason, method, path, body) => {
    setBusy(true);
    setMutationError(null);
    try {
      const stepUpToken = await requestGrant(reason, `${method} ${path}`);
      await apiRequest(path, { method, stepUpToken, body: body ? JSON.stringify(body) : undefined });
      reload();
      return true;
    } catch (err) {
      if (!isCancelled(err)) setMutationError(errorMessage(err, 'Could not change group'));
      return false;
    } finally { setBusy(false); }
  };
  const edit = (group?: DirectoryGroup) => {
    setSelected(null);
    setMutationError(null);
    setName(group?.name ?? '');
    setDescription(group?.description ?? '');
    setEditor(group ? { kind: 'edit', group } : { kind: 'new' });
  };
  return <div className="admin-page">
    <div className="page-header">
      <div><h1 className="page-title">Groups</h1>
        <p>{user ? `Membership for ${user.username}` : 'Organize directory users into groups.'}</p>
        <p className="text-muted text-sm">Administrator access is controlled by each user's role.</p>
      </div>
      {user ? <button className="secondary-btn" disabled={busy} onClick={onClearUser}>All groups</button>
        : <button className="primary-btn" disabled={busy} onClick={() => edit()}>Create group</button>}
    </div>
    {(mutationError || error) && <div className="alert-box error" role="alert">{mutationError || error}{error && <button className="secondary-btn sm" onClick={reload}>Retry</button>}</div>}
    {editor && <section className="settings-section" aria-labelledby="group-editor-title">
      <div className="section-header"><h2 id="group-editor-title">{editor.kind === 'new' ? 'Create group' : `Edit ${editor.group.name}`}</h2></div>
      <form className="modal-body" onSubmit={async (e: React.FormEvent) => {
        e.preventDefault();
        const path = editor.kind === 'new' ? '/api/admin/groups' : `/api/admin/groups/${editor.group.id}`;
        if (await mutate(`${editor.kind === 'new' ? 'Create' : 'Update'} group '${name.trim()}'.`, editor.kind === 'new' ? 'POST' : 'PUT', path,
          { name: name.trim(), description: description.trim() })) setEditor(null);
      }}>
        <div className="form-group"><label className="form-label" htmlFor="group-name">Name</label>
          <input id="group-name" autoFocus className="form-input" value={name} maxLength={128} required disabled={busy} onChange={e => setName(e.target.value)} /></div>
        <div className="form-group"><label className="form-label" htmlFor="group-description">Description</label>
          <textarea id="group-description" className="form-input" value={description} maxLength={2048} disabled={busy} onChange={e => setDescription(e.target.value)} /></div>
        <div className="modal-footer">
          <button type="button" className="secondary-btn" disabled={busy} onClick={() => setEditor(null)}>Cancel</button>
          <button className="primary-btn" disabled={busy || !name.trim()}>Save group</button>
        </div>
      </form>
    </section>}
    {!selected && <>
    <div className="form-group"><label className="form-label" htmlFor="group-search">Search groups</label>
      <input id="group-search" autoFocus className="form-input" value={query} maxLength={200} disabled={busy}
        onChange={e => { setQuery(e.target.value); setOffset(0); }} /></div>
    <div className="table-card"><table className="admin-table">
      <thead><tr><th>Name</th><th>Description</th><th>Members</th><th>{user ? 'Membership' : 'Actions'}</th></tr></thead>
      <tbody>{page?.items.map(group => <tr key={group.id}>
        <td style={{ overflowWrap: 'anywhere' }}>{group.name}</td><td style={{ maxWidth: '24rem', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{group.description}</td><td>{group.memberCount}</td>
        <td><div className="action-buttons-wrap">
          {user ? <button className="secondary-btn sm" disabled={busy} onClick={() => mutate(
            `${group.member ? 'Remove' : 'Add'} '${user.username}' ${group.member ? 'from' : 'to'} '${group.name}'.`,
            group.member ? 'DELETE' : 'PUT', `/api/admin/groups/${group.id}/members/${user.id}`)}>{group.member ? 'Remove member' : 'Add member'}</button> : <>
            <button className="secondary-btn sm" disabled={busy} onClick={() => { setEditor(null); setSelected(group); }}>Members</button>
            <button className="secondary-btn sm" disabled={busy} onClick={() => edit(group)}>Edit</button>
            <button className="secondary-btn sm" disabled={busy} onClick={async () => {
              if (await mutate(`Delete '${group.name}' and all of its memberships.`, 'DELETE', `/api/admin/groups/${group.id}`)) {
                if (editor?.kind === 'edit' && editor.group.id === group.id) setEditor(null);
              }
            }}>Delete</button>
          </>}
        </div></td>
      </tr>)}</tbody>
    </table></div>
    {page?.items.length === 0 && <p className="empty-box">No matching groups.</p>}
    <Pager page={page} offset={offset} onChange={setOffset} />
    </>}
    {selected && <GroupMembers key={selected.id} group={selected} busy={busy} mutate={mutate} onClose={() => setSelected(null)} />}
    {stepUpPrompt}
  </div>;
}
