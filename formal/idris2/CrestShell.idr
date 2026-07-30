module CrestShell

%default total

||| Crest shell workspace lattice. Four Plasma-style virtual desktops and a
||| single exclusive transient overlay owner mirror the Rust ShellState rules.

public export
data Overlay
  = None
  | Kickoff
  | KRunner
  | DesktopMenu
  | ControlCenter
  | Notifications
  | SystemTray
  | Session
  | TaskSwitcher
  | Calendar
  | WorkspaceOverview
  | Spectacle

public export
record Shell where
  constructor MkShell
  workspace : Nat
  overlay : Overlay

public export
data WorkspaceInBounds : Nat -> Type where
  Workspace0 : WorkspaceInBounds 0
  Workspace1 : WorkspaceInBounds 1
  Workspace2 : WorkspaceInBounds 2
  Workspace3 : WorkspaceInBounds 3

public export
selectWorkspace : Shell -> (workspace : Nat) -> WorkspaceInBounds workspace -> Shell
selectWorkspace shell workspace _ =
  MkShell workspace None

public export
openOverlay : Shell -> Overlay -> Shell
openOverlay shell None = shell
openOverlay (MkShell workspace _) overlay = MkShell workspace overlay

public export
closeOverlays : Shell -> Shell
closeOverlays (MkShell workspace _) = MkShell workspace None

public export
nextWorkspace : Nat -> Nat
nextWorkspace 0 = 1
nextWorkspace 1 = 2
nextWorkspace 2 = 3
nextWorkspace 3 = 0
nextWorkspace n = n

public export
previousWorkspace : Nat -> Nat
previousWorkspace 0 = 3
previousWorkspace 1 = 0
previousWorkspace 2 = 1
previousWorkspace 3 = 2
previousWorkspace n = n

public export
initialShell : Shell
initialShell = MkShell 0 None

public export
openingKickoffReplacesCalendar :
  openOverlay (MkShell 1 Calendar) Kickoff = MkShell 1 Kickoff
openingKickoffReplacesCalendar = Refl

public export
closeClearsAnyOverlay :
  closeOverlays (MkShell 2 Spectacle) = MkShell 2 None
closeClearsAnyOverlay = Refl

public export
workspaceWrapsForward :
  nextWorkspace 3 = 0
workspaceWrapsForward = Refl

public export
workspaceWrapsBackward :
  previousWorkspace 0 = 3
workspaceWrapsBackward = Refl

public export
selectWorkspaceClearsOverlay :
  selectWorkspace (MkShell 0 Kickoff) 2 Workspace2 = MkShell 2 None
selectWorkspaceClearsOverlay = Refl

public export
workspaceIndexValid : Nat -> Bool
workspaceIndexValid 0 = True
workspaceIndexValid 1 = True
workspaceIndexValid 2 = True
workspaceIndexValid 3 = True
workspaceIndexValid _ = False

public export
fifthWorkspaceRejected :
  workspaceIndexValid 4 = False
fifthWorkspaceRejected = Refl
