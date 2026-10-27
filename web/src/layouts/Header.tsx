import { useMemo } from "react"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { useLocation } from "react-router-dom"
import { Avatar } from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { User, Settings, Github, Book, Server, Menu, PanelLeftClose, PanelLeftOpen, Sun, Moon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import EnrollDialog from "@/components/dialogs/EnrollDialog"
import { CrowdSecLogo } from "@/components/icons/CrowdSecLogo"
import { useQuery } from "@tanstack/react-query"
import { hostsAPI, setSelectedHost, type HostInfo } from "@/lib/api"
import { useTheme } from "@/contexts/ThemeContext"

interface HeaderProps {
  onMenuClick?: () => void
  isCollapsed?: boolean
  onToggleCollapse?: () => void
}

export default function Header({ onMenuClick, isCollapsed, onToggleCollapse }: HeaderProps) {
  const location = useLocation()
  const { theme, setTheme } = useTheme()

  const { data: hostsData } = useQuery({
    queryKey: ['docker-hosts'],
    queryFn: () => hostsAPI.list(),
    staleTime: 30000,
  })

  const { data: authData } = useQuery({
    queryKey: ['auth-status'],
    queryFn: () => hostsAPI.authStatus(),
    staleTime: 30000,
  })

  const hosts: HostInfo[] = hostsData?.data?.data ?? []
  const showHostSelector = hosts.length >= 1
  const authStatus = authData?.data?.data

  const toggleTheme = () => {
    setTheme(theme === "dark" ? "light" : "dark")
  }

  // Generate breadcrumbs from path
  const pathSegments = location.pathname.split('/').filter(Boolean)
  const breadcrumbs = useMemo(() => [
    { name: 'Home', href: '/' },
    ...pathSegments.map((segment, index) => {
      const href = `/${pathSegments.slice(0, index + 1).join('/')}`
      return {
        name: segment.charAt(0).toUpperCase() + segment.slice(1).replace(/-/g, ' '),
        href
      }
    })
  ], [pathSegments])

  return (
    <header className="h-16 border-b border-sidebar-border bg-card px-6 flex items-center justify-between shadow-sm">
      {/* Left: Menu + Breadcrumbs */}
      <div className="flex items-center gap-4 min-w-0">
        {/* Mobile hamburger */}
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden h-9 w-9"
          onClick={onMenuClick}
        >
          <Menu className="h-5 w-5" />
        </Button>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="icon"
            className="hidden md:inline-flex h-9 w-9"
            onClick={onToggleCollapse}
          >
            {isCollapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
          </Button>
          <div className="flex flex-col min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-base font-semibold truncate">CrowdNinja</span>
              <Badge variant="secondary" className="text-[10px] px-1.5 py-0.5 uppercase">
                {import.meta.env.MODE}
              </Badge>
            </div>
            <Breadcrumb>
              <BreadcrumbList className="text-xs text-muted-foreground">
                {breadcrumbs.map((item, index) => (
                  <div key={item.href} className="flex items-center">
                    <BreadcrumbItem>
                      {index === breadcrumbs.length - 1 ? (
                        <BreadcrumbPage>{item.name}</BreadcrumbPage>
                      ) : (
                        <BreadcrumbLink href={item.href}>{item.name}</BreadcrumbLink>
                      )}
                    </BreadcrumbItem>
                    {index < breadcrumbs.length - 1 && (
                      <BreadcrumbSeparator />
                    )}
                  </div>
                ))}
              </BreadcrumbList>
            </Breadcrumb>
          </div>
        </div>
      </div>

      {/* Right Section: Links & User Profile */}
      <div className="flex items-center gap-4">
        {/* Host Selector */}
        {showHostSelector && (
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-muted-foreground" />
            <Select
              defaultValue=""
              onValueChange={(value) => setSelectedHost(value === 'default' ? null : value)}
            >
              <SelectTrigger className="w-40 h-9">
                <SelectValue placeholder="Default Host" />
              </SelectTrigger>
              <SelectContent>
                {hosts.map((host) => (
                  <SelectItem key={host.id} value={host.is_default ? 'default' : host.id}>
                    <span className="flex items-center gap-2">
                      <span className={`h-2 w-2 rounded-full ${host.connected ? 'bg-green-500' : 'bg-red-500'}`} />
                      {host.id}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
        {/* Social Links - hidden on mobile */}
        <div className="hidden md:flex items-center gap-2 mr-2">
          <Button variant="outline" asChild className="gap-2">
            <a
              href="https://github.com/JustShinobi/CrowdNinja"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Github className="h-4 w-4" />
              GitHub
            </a>
          </Button>
        </div>

        <Button
          variant="ghost"
          size="icon"
          onClick={toggleTheme}
          className="text-muted-foreground hover:bg-accent hover:text-accent-foreground shrink-0"
        >
          {theme === "dark" ? (
            <Sun className="h-5 w-5" />
          ) : (
            <Moon className="h-5 w-5" />
          )}
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Avatar className="h-8 w-8 cursor-pointer hover:opacity-80 transition-opacity bg-transparent">
              <CrowdSecLogo className="h-full w-full text-primary p-1" />
            </Avatar>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel>
              {authStatus?.authenticated && authStatus?.user
                ? `${authStatus.user.name} (${authStatus.user.provider.toUpperCase()})`
                : 'CrowdNinja Security'}
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            {authStatus?.enabled && !authStatus?.authenticated && (
              <DropdownMenuItem asChild>
                <a href={authStatus.login_url || '/api/auth/login'} className="cursor-pointer">
                  <User className="h-4 w-4" />
                  <span>Sign In (OIDC / SSO)</span>
                </a>
              </DropdownMenuItem>
            )}
            {authStatus?.authenticated && (
              <DropdownMenuItem
                onSelect={async () => {
                  await hostsAPI.logout()
                  window.location.reload()
                }}
                className="cursor-pointer"
              >
                <User className="h-4 w-4" />
                <span>Sign Out ({authStatus.user?.username})</span>
              </DropdownMenuItem>
            )}
            <EnrollDialog
              trigger={
                <DropdownMenuItem onSelect={(e) => e.preventDefault()} className="cursor-pointer">
                  <Settings className="h-4 w-4" />
                  <span>Enroll CrowdSec</span>
                </DropdownMenuItem>
              }
            />
            <DropdownMenuItem asChild>
              <a href="https://app.crowdsec.net/" target="_blank" rel="noopener noreferrer" className="cursor-pointer">
                <User className="h-4 w-4" />
                <span>Get your enroll key</span>
              </a>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <a href="https://docs.crowdsec.net/" target="_blank" rel="noopener noreferrer" className="cursor-pointer">
                <Book className="h-4 w-4" />
                <span>CrowdSec Documentation</span>
              </a>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
