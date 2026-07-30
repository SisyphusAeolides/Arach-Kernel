{-# OPTIONS --safe --without-K #-}

module CrestOverlay where

data Empty : Set where

Not : Set -> Set
Not proposition = proposition -> Empty

data Nat : Set where
  zero : Nat
  suc : Nat -> Nat

data _≡_ {A : Set} (x : A) : A -> Set where
  refl : x ≡ x

-- At most four workspaces. There is no fifth constructor.
data Workspace : Set where
  ws0 : Workspace
  ws1 : Workspace
  ws2 : Workspace
  ws3 : Workspace

-- Transient shell surfaces. Only one may own Escape at a time.
data Overlay : Set where
  none : Overlay
  kickoff : Overlay
  krunner : Overlay
  desktopMenu : Overlay
  controlCenter : Overlay
  notifications : Overlay
  systemTray : Overlay
  session : Overlay
  taskSwitcher : Overlay
  calendar : Overlay
  workspaceOverview : Overlay
  spectacle : Overlay

data Shell : Set where
  shell : Workspace -> Overlay -> Shell

data Exclusive : Overlay -> Set where
  openNone : Exclusive none
  openOne : (overlay : Overlay) -> Exclusive overlay

-- Applying a non-none overlay replaces the previous owner; there is no
-- constructor that stacks two primary overlays. Opening none is identity
-- (does not force-clear an existing overlay), matching Idris CrestShell.
openOverlay : Shell -> Overlay -> Shell
openOverlay s none = s
openOverlay (shell workspace _) overlay = shell workspace overlay

closeOverlays : Shell -> Shell
closeOverlays (shell workspace _) = shell workspace none

selectWorkspace : Shell -> Workspace -> Shell
selectWorkspace (shell _ _) workspace = shell workspace none

nextWorkspace : Workspace -> Workspace
nextWorkspace ws0 = ws1
nextWorkspace ws1 = ws2
nextWorkspace ws2 = ws3
nextWorkspace ws3 = ws0

previousWorkspace : Workspace -> Workspace
previousWorkspace ws0 = ws3
previousWorkspace ws1 = ws0
previousWorkspace ws2 = ws1
previousWorkspace ws3 = ws2

kickoffReplacesCalendar :
  openOverlay (shell ws1 calendar) kickoff ≡ shell ws1 kickoff
kickoffReplacesCalendar = refl

closeClearsSpectacle :
  closeOverlays (shell ws2 spectacle) ≡ shell ws2 none
closeClearsSpectacle = refl

workspaceWraps :
  nextWorkspace ws3 ≡ ws0
workspaceWraps = refl

selectClearsOverlay :
  selectWorkspace (shell ws0 krunner) ws2 ≡ shell ws2 none
selectClearsOverlay = refl

-- Exclusive open is inhabited for every single overlay, including none.
exclusiveKickoff : Exclusive kickoff
exclusiveKickoff = openOne kickoff

exclusiveNone : Exclusive none
exclusiveNone = openNone
