import { apiClient } from './client'
import type { ApiResponse, IPInfo, UnbanRequest } from './types'

export interface ASNRule {
  id?: number
  asn: string
  as_name: string
  action: string
  duration: string
  reason: string
  dry_run: boolean
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export interface ASNException {
  id?: number
  asn: string
  ip_or_cidr: string
  note: string
  created_at?: string
}

export const ipAPI = {
  getPublicIP: () =>
    apiClient.get<ApiResponse<{ ip: string }>>('/ip/public'),

  isBlocked: (ip: string) =>
    apiClient.get<ApiResponse<{ ip: string; blocked: boolean; details: string }>>(`/ip/blocked/${ip}`),

  checkSecurity: (ip: string) =>
    apiClient.get<ApiResponse<IPInfo>>(`/ip/security/${ip}`),

  unban: (data: UnbanRequest) =>
    apiClient.post<ApiResponse>('/ip/unban', data),

  listASNRules: () =>
    apiClient.get<ApiResponse<ASNRule[]>>('/asn/rules'),

  saveASNRule: (rule: Partial<ASNRule>) =>
    apiClient.post<ApiResponse<ASNRule>>('/asn/rules', rule),

  deleteASNRule: (asn: string) =>
    apiClient.delete<ApiResponse>(`/asn/rules/${encodeURIComponent(asn)}`),

  listASNExceptions: (asn?: string) =>
    apiClient.get<ApiResponse<ASNException[]>>('/asn/exceptions', { params: asn ? { asn } : undefined }),

  addASNException: (exc: Partial<ASNException>) =>
    apiClient.post<ApiResponse<ASNException>>('/asn/exceptions', exc),

  deleteASNException: (id: number) =>
    apiClient.delete<ApiResponse>(`/asn/exceptions/${id}`),
}
