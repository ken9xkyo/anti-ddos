import { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Checkbox, FormControlLabel, MenuItem, Stack, TextField, Typography } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { Eye, KeyRound, Plus, RotateCcw, ShieldCheck, Users } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, ConfirmDialog, InlineResult, ReasonField } from '../adminUi';
import { PanelHeader, StatusPill } from '../components';
import { formatDateTime } from '../format';
import type { Role, User, AllocatedCIDR, Agent } from '../types';

type UserForm = {
  reason: string;
  username: string;
  password: string;
  role: Role;
  status: string;
  force_password_change: boolean;
  default_output_interface: string;
};

const emptyUserForm: UserForm = {
  reason: 'update user access',
  username: '',
  password: '',
  role: 'user',
  status: 'active',
  force_password_change: true,
  default_output_interface: ''
};

export function AccessView({
  currentUser,
  onViewUserConfig,
  agents = []
}: {
  currentUser: User;
  onViewUserConfig?: (userID: string) => void | Promise<void>;
  agents?: Agent[];
}) {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');
  const [mode, setMode] = useState<'create' | 'edit' | 'reset' | 'cidrs' | ''>('');
  const [target, setTarget] = useState<User | null>(null);
  const [form, setForm] = useState<UserForm>(emptyUserForm);
  const [revokeTarget, setRevokeTarget] = useState<User | null>(null);
  const [reason, setReason] = useState('revoke user sessions');
  const [cidrs, setCidrs] = useState<AllocatedCIDR[]>([]);
  const [newCidr, setNewCidr] = useState('');
  const [cidrReason, setCidrReason] = useState('');
  const [cidrError, setCidrError] = useState('');
  const isAdmin = currentUser.role === 'admin';

  const outputInterfaces = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const agent of agents) {
      for (const iface of agent.interfaces ?? []) {
        const name = iface.name.trim();
        if (!name || seen.has(name)) continue;
        seen.add(name);
        out.push(name);
      }
    }
    return out.sort();
  }, [agents]);

  const load = async () => {
    try {
      setLoading(true);
      setUsers(await api.users());
      setResult('');
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'load users failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const columns = useMemo<GridColDef[]>(() => [
    { field: 'username', headerName: 'Username', flex: 1, minWidth: 150 },
    { field: 'role', headerName: 'Role', width: 120 },
    {
      field: 'status',
      headerName: 'Status',
      width: 125,
      renderCell: (params) => <StatusPill state={params.value === 'active' ? 'ok' : 'off'} text={params.value || 'active'} />
    },
    {
      field: 'force_password_change',
      headerName: 'Force change',
      width: 130,
      valueGetter: (_, row) => row.force_password_change ? 'yes' : 'no'
    },
    { field: 'last_login_at', headerName: 'Last login', width: 180, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    { field: 'created_at', headerName: 'Created', width: 180, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 290,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as User;
        if (!isAdmin) return <span className="muted">read only</span>;
        return (
          <Stack direction="row" spacing={0.75}>
            <Button size="small" variant="outlined" disabled={row.role !== 'user' || row.status === 'revoked' || !onViewUserConfig} onClick={() => onViewUserConfig?.(row.id)}><Eye size={14} />View config</Button>
            <Button size="small" variant="outlined" disabled={row.role !== 'user' || row.status === 'revoked'} onClick={() => openCidrs(row)}>CIDRs</Button>
            <Button size="small" variant="outlined" onClick={() => openEdit(row)}>Edit</Button>
            <Button size="small" variant="outlined" onClick={() => openReset(row)}>Reset</Button>
            <Button size="small" variant="outlined" color="warning" onClick={() => {
              setRevokeTarget(row);
              setReason(`revoke ${row.username} sessions`);
            }}>Sessions</Button>
          </Stack>
        );
      }
    }
  ], [isAdmin, onViewUserConfig]);

  function canManageUser(user: User | null) {
    return Boolean(user && isAdmin);
  }

  const openCreate = () => {
    setTarget(null);
    setForm({ ...emptyUserForm, reason: 'create user' });
    setMode('create');
  };

  const openEdit = (user: User) => {
    setTarget(user);
    setForm({
      ...emptyUserForm,
      reason: `update ${user.username}`,
      username: user.username,
      role: user.role,
      status: user.status ?? 'active',
      force_password_change: Boolean(user.force_password_change),
      default_output_interface: user.default_output_interface ?? ''
    });
    setMode('edit');
  };

  const openReset = (user: User) => {
    setTarget(user);
    setForm({ ...emptyUserForm, reason: `reset ${user.username} password`, username: user.username, role: user.role });
    setMode('reset');
  };

  const openCidrs = async (user: User) => {
    setTarget(user);
    setCidrError('');
    setNewCidr('');
    setCidrReason(`allocate CIDR to ${user.username}`);
    setMode('cidrs');
    try {
      setCidrs(await api.userAllocatedCIDRs(user.id));
    } catch (err) {
      setCidrError(err instanceof Error ? err.message : 'failed to load CIDRs');
    }
  };

  const addCidr = async () => {
    if (!target) return;
    setCidrError('');
    try {
      const added = await api.createAllocatedCIDR(target.id, { cidr: newCidr, reason: cidrReason });
      setCidrs([...cidrs, added]);
      setNewCidr('');
    } catch (err) {
      setCidrError(err instanceof Error ? err.message : 'failed to add CIDR');
    }
  };

  const deleteCidr = async (id: string) => {
    if (!target) return;
    setCidrError('');
    const reasonStr = prompt('Enter audit reason for deletion:', `delete CIDR for ${target.username}`);
    if (reasonStr === null) return;
    try {
      await api.deleteAllocatedCIDR(target.id, id, reasonStr || 'delete CIDR');
      setCidrs(cidrs.filter(c => c.id !== id));
    } catch (err) {
      setCidrError(err instanceof Error ? err.message : 'failed to delete CIDR');
    }
  };

  const submit = async () => {
    try {
      if (mode === 'create') {
        if (!isAdmin) return;
        await api.createUser({
          reason: form.reason,
          username: form.username,
          password: form.password,
          role: form.role,
          default_output_interface: form.role === 'user' ? form.default_output_interface : ''
        });
        setResult(`${form.username} created`);
      } else if (mode === 'edit' && target) {
        if (!canManageUser(target)) return;
        await api.updateUser(target.id, {
          reason: form.reason,
          role: form.role,
          status: form.status,
          force_password_change: form.force_password_change,
          default_output_interface: form.role === 'user' ? form.default_output_interface : ''
        });
        setResult(`${target.username} updated`);
      } else if (mode === 'reset' && target) {
        if (!canManageUser(target)) return;
        await api.resetUserPassword(target.id, {
          reason: form.reason,
          password: form.password,
          force_password_change: form.force_password_change
        });
        setResult(`${target.username} password reset`);
      }
      setMode('');
      await load();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'user mutation failed');
    }
  };

  const revokeSessions = async () => {
    const user = revokeTarget;
    if (!user || !canManageUser(user)) return;
    try {
      await api.revokeUserSessions(user.id, reason);
      setResult(`${user.username} sessions revoked`);
      setRevokeTarget(null);
      await load();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'session revoke failed');
    }
  };

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader
          icon={<Users size={18} />}
          title="Accounts"
          eyebrow="admin/user RBAC"
          actions={isAdmin ? <button type="button" className="primary-action" onClick={openCreate}><Plus size={15} />Add user</button> : null}
        />
        <InlineResult result={result} />
      </section>

      <AdminGrid rows={users} columns={columns} loading={loading} emptyText="No users" height={520} />

      <AdminDrawer
        open={mode === 'create' || mode === 'edit' || mode === 'reset'}
        title={mode === 'create' ? 'Add User' : mode === 'reset' ? `Reset ${target?.username ?? 'user'} Password` : `Edit ${target?.username ?? 'user'}`}
        onClose={() => setMode('')}
        actions={<>
          <Button onClick={() => setMode('')}>Cancel</Button>
          <Button variant="contained" onClick={submit} startIcon={mode === 'reset' ? <KeyRound size={16} /> : <ShieldCheck size={16} />}>Save</Button>
        </>}
      >
        {mode === 'create' ? <TextField label="Username" value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} fullWidth required /> : null}
        {mode === 'create' || mode === 'reset' ? <TextField label="Temporary password" type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} fullWidth required /> : null}
        {mode !== 'reset' ? (
          <>
            <TextField select label="Role" value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value as Role })} fullWidth>
              <MenuItem value="user">User</MenuItem>
              <MenuItem value="admin">Admin</MenuItem>
            </TextField>
            <TextField select label="Status" value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value })} fullWidth>
              <MenuItem value="active">Active</MenuItem>
              <MenuItem value="revoked">Revoked</MenuItem>
            </TextField>
            {form.role === 'user' ? (
              <TextField
                select
                label="Default output interface"
                value={form.default_output_interface}
                onChange={(event) => setForm({ ...form, default_output_interface: event.target.value })}
                fullWidth
                helperText="Default network interface assigned for user services"
              >
                <MenuItem value="">None / Not Assigned</MenuItem>
                {outputInterfaces.map((iface) => (
                  <MenuItem key={iface} value={iface}>
                    {iface}
                  </MenuItem>
                ))}
              </TextField>
            ) : null}
          </>
        ) : null}
        <FormControlLabel control={<Checkbox checked={form.force_password_change} onChange={(event) => setForm({ ...form, force_password_change: event.target.checked })} />} label="Force password change" />
        <ReasonField value={form.reason} onChange={(value) => setForm({ ...form, reason: value })} />
      </AdminDrawer>

      <AdminDrawer
        open={mode === 'cidrs'}
        title={`Manage ${target?.username ?? 'user'}'s CIDR Allocations`}
        onClose={() => setMode('')}
        actions={<Button onClick={() => setMode('')}>Close</Button>}
      >
        {cidrError ? <Alert severity="error">{cidrError}</Alert> : null}
        
        <Stack spacing={1} sx={{ mb: 2 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>Allocated CIDRs</Typography>
          {cidrs.length === 0 ? (
            <Typography variant="body2" color="text.secondary">No CIDR blocks allocated.</Typography>
          ) : (
            cidrs.map((c) => (
              <Stack key={c.id} direction="row" spacing={2} sx={{ borderBottom: '1px solid rgba(148,163,184,0.1)', pb: 1, alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{c.cidr}</Typography>
                <Button size="small" variant="text" color="error" onClick={() => deleteCidr(c.id)}>Delete</Button>
              </Stack>
            ))
          )}
        </Stack>

        <Stack spacing={1.5} sx={{ borderTop: '1px solid rgba(148,163,184,0.2)', pt: 2 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>Allocate New CIDR</Typography>
          <TextField
            label="CIDR (e.g. 192.168.1.0/24)"
            value={newCidr}
            onChange={(e) => setNewCidr(e.target.value)}
            fullWidth
            size="small"
          />
          <TextField
            label="Audit Reason"
            value={cidrReason}
            onChange={(e) => setCidrReason(e.target.value)}
            fullWidth
            size="small"
          />
          <Button variant="contained" onClick={addCidr} disabled={!newCidr.trim()}>Allocate CIDR</Button>
        </Stack>
      </AdminDrawer>

      <ConfirmDialog
        open={Boolean(revokeTarget)}
        title={`Revoke ${revokeTarget?.username ?? 'user'} Sessions`}
        confirmText="Revoke sessions"
        onCancel={() => setRevokeTarget(null)}
        onConfirm={revokeSessions}
      >
        <Stack spacing={1.5}>
          <ReasonField value={reason} onChange={setReason} />
          <div className="muted"><RotateCcw size={14} /> Active sessions for this user will be invalidated.</div>
        </Stack>
      </ConfirmDialog>
    </section>
  );
}
