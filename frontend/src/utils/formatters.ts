/**
 * RESILIX Formatting & Timestamp Utilities
 * Converts backend UTC ISO-8601 strings to consistent local timezone display.
 */

export function formatLocalTime(isoUtc?: string | null): string {
  if (!isoUtc) return '—';
  try {
    const dt = new Date(isoUtc);
    if (isNaN(dt.getTime())) return isoUtc;
    return dt.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return isoUtc;
  }
}

export function formatLocalDateTime(isoUtc?: string | null): string {
  if (!isoUtc) return '—';
  try {
    const dt = new Date(isoUtc);
    if (isNaN(dt.getTime())) return isoUtc;
    return dt.toLocaleString([], {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return isoUtc;
  }
}

export function getStatusBadgeStyle(status?: string): string {
  switch (status) {
    case 'HEALTHY':
    case 'OK':
    case 'SYNCED':
    case 'VERIFIED_INTACT':
    case 'ACCEPTED':
    case 'PASS':
      return 'bg-[#138B87]/15 text-[#138B87] border border-[#138B87]/30';
    case 'WARNING':
    case 'ACKNOWLEDGED':
    case 'PENDING':
    case 'SYNCING':
    case 'SUSPECT':
    case 'MISSING_SENSOR':
    case 'STALE_DATA':
    case 'INCONSISTENT_SIGNAL':
      return 'bg-[#E5A13B]/15 text-[#B47112] border border-[#E5A13B]/40';
    case 'CRITICAL':
    case 'OPEN':
    case 'REJECTED':
    case 'FAILED':
    case 'IMPLAUSIBLE_READING':
    case 'INTEGRITY_COMPROMISED':
      return 'bg-[#C84040]/15 text-[#C84040] border border-[#C84040]/35';
    default:
      return 'bg-slate-100 text-slate-600 border border-slate-300';
  }
}
