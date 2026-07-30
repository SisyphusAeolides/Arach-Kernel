module GraniteBoot

%default total

public export
data ArtifactState
  = Missing
  | Empty
  | Oversized
  | TruncatedHeader
  | UnsupportedEncoding
  | UnsupportedMachine
  | InvalidProgramTable
  | InvalidSegmentLayout
  | InvalidEntry
  | ManifestMissing
  | DigestMismatch
  | Ready

public export
record BootBundle where
  constructor MkBootBundle
  boulder : ArtifactState
  push : ArtifactState
  crest : ArtifactState
  ||| Optional measured Hermes GSP module. Missing is legal; a present but
  ||| unready Hermes image rejects preflight so Granite never transports a
  ||| corrupt offload candidate into Boulder.
  hermes : ArtifactState

public export
data GranitePhase
  = Firmware
  | Preflighted
  | Measured
  | Transferred
  | Rejected

public export
hermesOptionalReady : ArtifactState -> Bool
hermesOptionalReady Missing = True
hermesOptionalReady Ready = True
hermesOptionalReady _ = False

public export
preflight : BootBundle -> GranitePhase
preflight (MkBootBundle Ready Ready Ready hermes) =
  if hermesOptionalReady hermes then Preflighted else Rejected
preflight _ = Rejected

public export
measure : GranitePhase -> GranitePhase
measure Preflighted = Measured
measure phase = phase

public export
transfer : GranitePhase -> GranitePhase
transfer Measured = Transferred
transfer phase = phase

public export
missingArtifactRejects :
  preflight (MkBootBundle Missing Ready Ready Missing) = Rejected
missingArtifactRejects = Refl

public export
truncatedArtifactRejects :
  preflight (MkBootBundle Ready TruncatedHeader Ready Missing) = Rejected
truncatedArtifactRejects = Refl

misalignedOrOverlappingArtifactRejects :
  preflight (MkBootBundle Ready InvalidSegmentLayout Ready Missing) = Rejected
misalignedOrOverlappingArtifactRejects = Refl

nonExecutableEntryRejects :
  preflight (MkBootBundle Ready InvalidEntry Ready Missing) = Rejected
nonExecutableEntryRejects = Refl

missingMeasurementManifestRejects :
  preflight (MkBootBundle Ready ManifestMissing Ready Missing) = Rejected
missingMeasurementManifestRejects = Refl

digestMismatchRejects :
  preflight (MkBootBundle Ready DigestMismatch Ready Missing) = Rejected
digestMismatchRejects = Refl

public export
corruptHermesModuleRejects :
  preflight (MkBootBundle Ready Ready Ready DigestMismatch) = Rejected
corruptHermesModuleRejects = Refl

public export
boundedReadyBundlePreflights :
  preflight (MkBootBundle Ready Ready Ready Missing) = Preflighted
boundedReadyBundlePreflights = Refl

public export
readyHermesModulePreflights :
  preflight (MkBootBundle Ready Ready Ready Ready) = Preflighted
readyHermesModulePreflights = Refl

public export
transferRequiresMeasurement :
  transfer Preflighted = Preflighted
transferRequiresMeasurement = Refl

public export
measuredBundleCanTransfer :
  transfer (measure Preflighted) = Transferred
measuredBundleCanTransfer = Refl
