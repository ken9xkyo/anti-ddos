export function numberValue(value: number | undefined): string {
  return Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value || 0);
}

export function compactValue(value: number | undefined): string {
  return Intl.NumberFormat(undefined, {
    notation: 'compact',
    maximumFractionDigits: 1
  }).format(value || 0);
}

export function percentValue(value: number | undefined): string {
  return `${Math.round((value || 0) * 100)}%`;
}

export function formatTime(value: string | undefined): string {
  if (!value) {
    return 'pending';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).format(date);
}

export function formatDateTime(value: string | undefined): string {
  if (!value) {
    return 'pending';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).format(date);
}

export function durationValue(seconds: number | undefined): string {
  const value = Math.max(0, Math.floor(seconds || 0));
  if (value >= 3600) {
    return `${Math.floor(value / 3600)}h ${Math.floor((value % 3600) / 60)}m`;
  }
  if (value >= 60) {
    return `${Math.floor(value / 60)}m ${value % 60}s`;
  }
  return `${value}s`;
}

export function jsonPreview(value: unknown): string {
  if (value === null || value === undefined || value === '') {
    return '{}';
  }
  if (typeof value === 'string') {
    return value;
  }
  return JSON.stringify(value, null, 2);
}
