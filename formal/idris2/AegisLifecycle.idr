module AegisLifecycle

%default total

public export
data Phase
  = Stopped
  | Starting
  | Running
  | Backoff
  | Failed

public export
record ServiceBinding where
  constructor MkServiceBinding
  phase : Phase
  pid : Nat

public export
valid : ServiceBinding -> Bool
valid (MkServiceBinding Running pid) = not (pid == 0)
valid (MkServiceBinding _ pid) = pid == 0

public export
canObserve : ServiceBinding -> Nat -> Bool
canObserve (MkServiceBinding Running pid) caller =
  if pid == 0 then False else pid == caller
canObserve _ _ = False

public export
start : ServiceBinding -> ServiceBinding
start (MkServiceBinding Stopped 0) = MkServiceBinding Starting 0
start binding = binding

public export
bind : ServiceBinding -> Nat -> ServiceBinding
bind (MkServiceBinding Starting 0) pid =
  if pid == 0 then MkServiceBinding Starting 0 else MkServiceBinding Running pid
bind binding _ = binding

public export
recordExit : Bool -> ServiceBinding -> Nat -> ServiceBinding
recordExit restartable (MkServiceBinding Running pid) observed =
  if pid == observed
    then if restartable then MkServiceBinding Backoff 0 else MkServiceBinding Failed 0
    else MkServiceBinding Running pid
recordExit _ binding _ = binding

public export
stop : ServiceBinding -> Nat -> ServiceBinding
stop binding caller = recordExit False binding caller

public export
data ImageState
  = Retained
  | Deferred
  | Reclaimed

public export
deferStoppedImage : ServiceBinding -> Nat -> ImageState -> ImageState
deferStoppedImage binding caller image =
  case stop binding caller of
    MkServiceBinding Failed 0 => RetainedOrDeferred image
    _ => image
  where
  RetainedOrDeferred : ImageState -> ImageState
  RetainedOrDeferred Retained = Deferred
  RetainedOrDeferred Deferred = Deferred
  RetainedOrDeferred Reclaimed = Reclaimed

public export
reapAfterRootSwitch : Bool -> ImageState -> ImageState
reapAfterRootSwitch rootChanged Deferred =
  if rootChanged then Reclaimed else Deferred
reapAfterRootSwitch _ image = image

public export
startLeavesNoStalePid :
  start (MkServiceBinding Stopped 0) = MkServiceBinding Starting 0
startLeavesNoStalePid = Refl

public export
zeroPidCannotBind :
  bind (MkServiceBinding Starting 0) 0 = MkServiceBinding Starting 0
zeroPidCannotBind = Refl

public export
livePidBindsRunning :
  bind (MkServiceBinding Starting 0) 41 = MkServiceBinding Running 41
livePidBindsRunning = Refl

public export
wrongPidCannotExit :
  recordExit True (MkServiceBinding Running 41) 42 = MkServiceBinding Running 41
wrongPidCannotExit = Refl

public export
restartableExitEntersBackoff :
  recordExit True (MkServiceBinding Running 41) 41 = MkServiceBinding Backoff 0
restartableExitEntersBackoff = Refl

public export
singleUseExitFailsTerminally :
  recordExit False (MkServiceBinding Running 41) 41 = MkServiceBinding Failed 0
singleUseExitFailsTerminally = Refl

public export
runningBindingRetainsLivePid :
  valid (MkServiceBinding Running 41) = True
runningBindingRetainsLivePid = Refl

public export
exactLivePidCanObserve :
  canObserve (MkServiceBinding Running 41) 41 = True
exactLivePidCanObserve = Refl

public export
foreignOrStalePidCannotObserve :
  canObserve (MkServiceBinding Running 41) 42 = False
foreignOrStalePidCannotObserve = Refl

public export
stopRequiresTheExactRunningPid :
  stop (MkServiceBinding Running 41) 42 = MkServiceBinding Running 41
stopRequiresTheExactRunningPid = Refl

public export
singleUseStopIsTerminal :
  stop (MkServiceBinding Running 41) 41 = MkServiceBinding Failed 0
singleUseStopIsTerminal = Refl

public export
foreignCallerCannotDeferImage :
  deferStoppedImage (MkServiceBinding Running 41) 42 Retained = Retained
foreignCallerCannotDeferImage = Refl

public export
exactStopDefersTheRetainedImage :
  deferStoppedImage (MkServiceBinding Running 41) 41 Retained = Deferred
exactStopDefersTheRetainedImage = Refl

public export
activeRootCannotReapDeferredImage :
  reapAfterRootSwitch False Deferred = Deferred
activeRootCannotReapDeferredImage = Refl

public export
rootSwitchReclaimsOnlyDeferredImage :
  reapAfterRootSwitch True Deferred = Reclaimed
rootSwitchReclaimsOnlyDeferredImage = Refl
