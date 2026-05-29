import { FormEvent, useEffect, useState } from 'react';
import { AlertTriangle, ListChecks, Save, Send } from 'lucide-react';
import { api } from '../client';
import { EmptyTableRow, JsonBlock, KeyValue, KeyValueGrid, PanelHeader, StatusPill, TablePanel } from '../components';
import { formatDateTime, jsonPreview } from '../format';
import type { Alert, TelegramConfig, TelegramConfigInput, User } from '../types';

type TelegramFormState = {
  bot_token_ref: string;
  chat_id: string;
  parse_mode: string;
  enabled: boolean;
  reason: string;
};

export function IncidentsView({
  alerts,
  config,
  user,
  canMutate,
  onRefresh
}: {
  alerts: Alert[];
  config: TelegramConfig;
  user: User;
  canMutate: boolean;
  onRefresh: () => void | Promise<void>;
}) {
  const [working, setWorking] = useState('');
  const [result, setResult] = useState('');
  const [telegramForm, setTelegramForm] = useState<TelegramFormState>(() => telegramFormFromConfig(config));
  const canConfigureTelegram = user.role === 'admin';

  useEffect(() => {
    setTelegramForm(telegramFormFromConfig(config));
  }, [config]);

  const runAction = async (action: 'test' | 'isp') => {
    if (!canMutate) return;
    try {
      setWorking(action);
      const alert = action === 'test' ? await api.testTelegram() : await api.evaluateIspEscalation();
      setResult(`${alert.type}: ${alert.status}`);
      await onRefresh();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'request failed');
    } finally {
      setWorking('');
    }
  };

  const saveTelegramConfig = async (event: FormEvent) => {
    event.preventDefault();
    if (!canConfigureTelegram) return;
    try {
      setWorking('telegram');
      const input: TelegramConfigInput = {
        reason: telegramForm.reason,
        bot_token_ref: telegramForm.bot_token_ref,
        chat_id: telegramForm.chat_id,
        parse_mode: telegramForm.parse_mode,
        enabled: telegramForm.enabled
      };
      await api.configureTelegram(input);
      setResult('telegram config saved');
      await onRefresh();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'request failed');
    } finally {
      setWorking('');
    }
  };

  const latestEscalation = alerts.find((alert) => alert.type === 'isp_escalation_needed');
  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader icon={<Send size={18} />} title="Telegram Channel" />
        <KeyValueGrid>
          <KeyValue label="State" value={<StatusPill state={config.enabled && config.bot_token_present ? 'ok' : 'warn'} text={config.enabled ? 'enabled' : 'disabled'} />} />
          <KeyValue label="Token" value={config.bot_token_present ? 'present' : 'missing'} />
          <KeyValue label="Chat" value={config.chat_id || 'not configured'} />
          <KeyValue label="Parse mode" value={config.parse_mode || 'plain text'} />
        </KeyValueGrid>

        {canConfigureTelegram ? (
          <form className="form-grid" onSubmit={saveTelegramConfig}>
            <label>
              Bot token ref
              <input value={telegramForm.bot_token_ref} onChange={(event) => setTelegramForm({ ...telegramForm, bot_token_ref: event.target.value })} placeholder="env://TELEGRAM_TOKEN" />
            </label>
            <label>
              Chat ID
              <input value={telegramForm.chat_id} onChange={(event) => setTelegramForm({ ...telegramForm, chat_id: event.target.value })} />
            </label>
            <label>
              Parse mode
              <select value={telegramForm.parse_mode} onChange={(event) => setTelegramForm({ ...telegramForm, parse_mode: event.target.value })}>
                <option value="">Plain text</option>
                <option value="HTML">HTML</option>
                <option value="MarkdownV2">MarkdownV2</option>
                <option value="Markdown">Markdown</option>
              </select>
            </label>
            <label>
              Reason
              <input value={telegramForm.reason} onChange={(event) => setTelegramForm({ ...telegramForm, reason: event.target.value })} placeholder="configure alert channel" />
            </label>
            <label className="checkbox-field">
              <input type="checkbox" checked={telegramForm.enabled} onChange={(event) => setTelegramForm({ ...telegramForm, enabled: event.target.checked })} />
              Enabled
            </label>
            <div className="form-actions">
              <button type="submit" className="primary-action" disabled={working !== ''}>
                <Save size={15} />{working === 'telegram' ? 'Saving' : 'Save config'}
              </button>
            </div>
          </form>
        ) : (
          <p className="muted">Telegram configuration changes require admin role.</p>
        )}

        <div className="button-row">
          <button type="button" className="secondary-action" disabled={!canMutate || working !== ''} onClick={() => runAction('test')}>
            <Send size={15} />{working === 'test' ? 'Testing' : 'Test alert'}
          </button>
          <button type="button" className="secondary-action" disabled={!canMutate || working !== ''} onClick={() => runAction('isp')}>
            <AlertTriangle size={15} />{working === 'isp' ? 'Evaluating' : 'ISP runbook'}
          </button>
          {result ? <span className={result.includes('failed') || result.includes('request') ? 'error-line inline-message' : 'success-line inline-message'}>{result}</span> : null}
        </div>
      </section>

      <TablePanel icon={<AlertTriangle size={18} />} title="Alerts" eyebrow={`${alerts.length} recent`}>
        <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Service</th><th>Vector</th><th>Status</th><th>Delivery</th><th>Action</th></tr></thead>
        <tbody>{alerts.length === 0 ? (
          <EmptyTableRow colSpan={8} text="No alerts in the current window" />
        ) : alerts.map((alert) => {
          const delivery = alert.deliveries?.[alert.deliveries.length - 1];
          return (
            <tr key={alert.id}>
              <td>{formatDateTime(alert.created_at)}</td>
              <td><StatusPill state={alert.severity === 'critical' ? 'danger' : alert.severity === 'warning' ? 'warn' : 'info'} text={alert.severity} /></td>
              <td>{alert.type}</td>
              <td>{alert.affected_service || alert.service_id || 'n/a'}</td>
              <td>{alert.vector || 'n/a'}</td>
              <td>{alert.status}</td>
              <td>{delivery ? `${delivery.status} #${delivery.attempt}` : 'pending'}</td>
              <td>{alert.recommended_action || 'investigate'}</td>
            </tr>
          );
        })}</tbody>
      </TablePanel>

      <section className="wide-panel">
        <PanelHeader icon={<ListChecks size={18} />} title="ISP Escalation Runbook" />
        <KeyValueGrid>
          <KeyValue label="Mode" value="Manual escalation only" />
          <KeyValue label="Automation" value="No automatic BGP, RTBH or FlowSpec action" />
          <KeyValue label="Target" value={latestEscalation?.affected_service || 'Select affected service from incident evidence'} />
          <KeyValue label="Vector" value={latestEscalation?.vector || 'link_saturation'} />
        </KeyValueGrid>
        <JsonBlock value={jsonPreview(latestEscalation?.evidence ?? {
          manual_only: true,
          target: 'affected target',
          vector: 'link_saturation',
          required: ['peak_bps', 'peak_pps', 'start_time', 'top_sources']
        })} />
      </section>
    </section>
  );
}

function telegramFormFromConfig(config: TelegramConfig): TelegramFormState {
  return {
    bot_token_ref: config.bot_token_ref,
    chat_id: config.chat_id,
    parse_mode: config.parse_mode ?? '',
    enabled: config.enabled,
    reason: 'update Telegram alert config'
  };
}
