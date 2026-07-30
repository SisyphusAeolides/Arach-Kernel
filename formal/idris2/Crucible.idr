module Crucible

%default total

public export
record SourceSurface where
  constructor MkSourceSurface
  lockedClosure : Bool
  publishedSourceLock : Bool
  hasBuildScript : Bool
  usesStd : Bool
  usesOpaqueFfi : Bool
  usesUnverifiedVectorState : Bool

public export
data Admission
  = Rejected
  | Admitted

safe : SourceSurface -> Bool
safe surface =
  lockedClosure surface &&
  publishedSourceLock surface &&
  not (hasBuildScript surface) &&
  not (usesStd surface) &&
  not (usesOpaqueFfi surface) &&
  not (usesUnverifiedVectorState surface)

public export
admit : SourceSurface -> Admission
admit surface = if safe surface then Admitted else Rejected

public export
buildScriptRejects :
  admit (MkSourceSurface True True True False False False) = Rejected
buildScriptRejects = Refl

public export
stdRejects :
  admit (MkSourceSurface True True False True False False) = Rejected
stdRejects = Refl

public export
opaqueFfiRejects :
  admit (MkSourceSurface True True False False True False) = Rejected
opaqueFfiRejects = Refl

public export
vectorStateRejects :
  admit (MkSourceSurface True True False False False True) = Rejected
vectorStateRejects = Refl

public export
lockedNativeSourceAdmits :
  admit (MkSourceSurface True True False False False False) = Admitted
lockedNativeSourceAdmits = Refl
