import { ALERTS_KEY } from '@/lib/live/alert-events';
import { api } from './client';
import type { Id, IsoDate, Paged } from './types';

/** Alerts, alert rules and notification channels (`server/src/Dranzo.Api/Features/AlertEndpoints.cs`). */

export type AlertState = 'open' | 'acknowledged' | 'resolved';
export const ALERT_STATES: readonly AlertState[] = ['open', 'acknowledged', 'resolved'];

export type Severity = 'info' | 'warning' | 'critical';

export interface Alert {
  id: Id;
  deviceId: Id;
  hostname: string;
  organizationId: Id;
  type: string;
  severity: Severity | (string & {});
  title: string;
  detail: string;
  state: AlertState;
  openedAt: IsoDate;
  acknowledgedAt: IsoDate | null;
  resolvedAt: IsoDate | null;
  notifiedAt: IsoDate | null;
}

export interface AlertFilter {
  state?: AlertState;
  organizationId?: Id;
  deviceId?: Id;
  severity?: string;
  page?: number;
  pageSize?: number;
}

export interface AlertRule {
  id: Id;
  name: string;
  type: string;
  severity: Severity | (string & {});
  enabled: boolean;
  /** `null` = applies to every organization (needs partner-wide scope to create or change). */
  organizationId: Id | null;
  channelIds: Id[];
  params: Record<string, unknown>;
}

export interface AlertRuleInput {
  name?: string;
  /** Only read by the server when creating. */
  type?: string;
  severity?: string;
  params?: Record<string, unknown>;
  enabled?: boolean;
  channelIds?: Id[];
  /** Only read by the server when creating. */
  organizationId?: Id | null;
}

export interface AlertCatalog {
  types: string[];
  severities: string[];
  webhookEvents: string[];
}

export type ChannelType = 'email' | 'webhook' | 'teams' | 'slack';
export const CHANNEL_TYPES: readonly ChannelType[] = ['email', 'webhook', 'teams', 'slack'];

/** The server never returns a channel's URL or secret: only the host name and whether a secret is set. */
export interface NotificationChannel {
  id: Id;
  name: string;
  type: ChannelType | (string & {});
  organizationId: Id | null;
  enabled: boolean;
  eventTypes: string[];
  createdAt: IsoDate;
  to: string[] | null;
  urlHost: string | null;
  hasSecret: boolean;
}

/** Fields left out of an update keep their stored value (that is how a secret stays unchanged). */
export interface ChannelInput {
  name?: string;
  type?: ChannelType;
  organizationId?: Id | null;
  enabled?: boolean;
  to?: string[];
  url?: string;
  secret?: string;
  eventTypes?: string[];
}

export interface ChannelDelivery {
  id: Id;
  eventType: string;
  createdAt: IsoDate;
  deliveredAt: IsoDate | null;
  attempts: number;
  lastError: string | null;
}

export const alertsApi = {
  list: (filter: AlertFilter, signal?: AbortSignal) =>
    api.get<Paged<Alert>>('/alerts', { query: { ...filter }, signal }),
  acknowledge: (id: Id) => api.post(`/alerts/${id}/acknowledge`),
  resolve: (id: Id) => api.post(`/alerts/${id}/resolve`),
  catalog: () => api.get<AlertCatalog>('/alert-rules/types'),
  rules: () => api.get<AlertRule[]>('/alert-rules'),
  createRule: (input: AlertRuleInput) => api.post<{ id: Id }>('/alert-rules', input),
  updateRule: (id: Id, input: AlertRuleInput) => api.patch(`/alert-rules/${id}`, input),
  deleteRule: (id: Id) => api.delete(`/alert-rules/${id}`),
  channels: () => api.get<NotificationChannel[]>('/notification-channels'),
  createChannel: (input: ChannelInput) => api.post<{ id: Id }>('/notification-channels', input),
  updateChannel: (id: Id, input: ChannelInput) => api.patch(`/notification-channels/${id}`, input),
  deleteChannel: (id: Id) => api.delete(`/notification-channels/${id}`),
  /** Queues a test notification; the result shows up in the channel's deliveries. */
  testChannel: (id: Id) => api.post(`/notification-channels/${id}/test`),
  deliveries: (id: Id) => api.get<ChannelDelivery[]>(`/notification-channels/${id}/deliveries`),
};

export const alertKeys = {
  /** Lists and counts; invalidated by the live `alert` event. */
  all: ALERTS_KEY,
  list: (filter: AlertFilter) => [...ALERTS_KEY, 'list', filter] as const,
  openCount: (organizationId?: Id) => [...ALERTS_KEY, 'open-count', organizationId ?? 'all'] as const,
  catalog: ['alert-rules', 'catalog'] as const,
  rules: ['alert-rules', 'list'] as const,
  channels: ['notification-channels'] as const,
  deliveries: (id: Id) => ['notification-channels', id, 'deliveries'] as const,
};
