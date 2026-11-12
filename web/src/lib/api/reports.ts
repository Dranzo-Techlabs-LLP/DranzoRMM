import { api, buildUrl } from './client';
import type { Id } from './types';

/** Reports (`server/src/Dranzo.Api/Features/ReportEndpoints.cs`). */

export interface ReportDef {
  id: string;
  name: string;
  /** Permission the download endpoint needs. */
  permission: string;
}

export type ReportFormat = 'csv' | 'pdf';

export const reportsApi = {
  list: () => api.get<ReportDef[]>('/reports'),
  /** Same-origin download link; the browser sends the session cookie itself. */
  downloadUrl: (reportId: string, format: ReportFormat, organizationId?: Id | null) =>
    buildUrl(`/reports/${encodeURIComponent(reportId)}.${format}`, { organizationId }),
};

export const reportKeys = { list: ['reports'] as const };
