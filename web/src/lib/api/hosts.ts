import { apiClient } from './client'
import type { ApiResponse, HostInfo } from './types'

export interface AuthUser {
  sub: string
  username: string
  name: string
  email: string
  groups: string[]
  provider: string
}

export interface AuthStatusResponse {
  enabled: boolean
  mode: string
  authenticated: boolean
  user?: AuthUser | null
  login_url: string
}

export const hostsAPI = {
  list: () =>
    apiClient.get<ApiResponse<HostInfo[]>>('/hosts/list'),

  registerLAPI: (data: { id: string; lapi_url: string; config_file?: string }) =>
    apiClient.post<ApiResponse>('/hosts/lapi', data),

  removeLAPI: (id: string) =>
    apiClient.delete<ApiResponse>(`/hosts/lapi/${encodeURIComponent(id)}`),

  authStatus: () =>
    apiClient.get<ApiResponse<AuthStatusResponse>>('/auth/status'),

  logout: () =>
    apiClient.post<ApiResponse>('/auth/logout'),
}
