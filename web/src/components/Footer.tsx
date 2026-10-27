export default function Footer() {
  return (
    <footer className="border-t border-border bg-card px-6 py-3">
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <div className="flex items-center gap-4">
          <span>CrowdNinja — Cloud-Native Security Operations for CrowdSec</span>
        </div>
        <div className="flex items-center gap-4">
          <span>&copy; {new Date().getFullYear()} CrowdNinja Contributors</span>
        </div>
      </div>
    </footer>
  )
}
