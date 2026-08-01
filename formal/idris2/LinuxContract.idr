||| Total certificate hierarchy for Linux build and NVIDIA runtime contracts.
module LinuxContract

%default total

public export
data Gate
  = ExternalKbuild
  | GeneratedConfiguration
  | SymbolVersions
  | Modpost
  | ModuleLinkerScripts
  | LinuxHeaders
  | LinuxModuleElf
  | KpiMemory
  | PciDeviceModel
  | DmaAndIommu
  | MsiAndIrq
  | Synchronization
  | WorkqueuesAndTimers
  | DeviceAndDriverModel
  | DrmAndKms
  | FirmwareLoading
  | ModuleLifecycle
  | SharedAddressSpaceClone
  | SharedDescriptorTable
  | DistinctThreadIdentity
  | PerThreadTls
  | PrivateFutexBlock
  | ClearChildTidWake
  | RobustListRegistration
  | OwnerDeathPublication
  | RobustFutexWake
  | SignalDisposition
  | SignalMaskAndPending
  | RtSignalFrame
  | RtSignalReturn
  | ThreadGroupSnapshot
  | PeerGenerationRetirement
  | LeaderZombiePublication
  | SupervisorReap
  | ImmutableFileSnapshot
  | BoundedExecVectors
  | MeasuredStaticImage
  | InactiveActivation
  | AtomicImageExchange
  | ExecStateReset
  | DeferredImageReap
  | RollbackPreservesImage
  | AtomicExecutablePairSnapshot
  | MeasuredRuntimeLinker
  | CompositeImageInstall
  | LinuxAuxiliaryVector
  | RuntimeLinkerEntry
  | MainEntryTransfer

||| A measurement is tied to one named gate and contains at least one case.
public export
record Measurement (gate : Gate) where
  constructor MkMeasurement
  suite : String
  firstPassingCase : String
  additionalPassingCases : List String
  artifactDigest : String

public export
record ExternalModuleCertificate where
  constructor MkExternalModuleCertificate
  externalKbuild : Measurement ExternalKbuild
  generatedConfiguration : Measurement GeneratedConfiguration
  symbolVersions : Measurement SymbolVersions
  modpost : Measurement Modpost
  moduleLinkerScripts : Measurement ModuleLinkerScripts
  linuxHeaders : Measurement LinuxHeaders
  linuxModuleElf : Measurement LinuxModuleElf

public export
record NvidiaRuntimeCertificate where
  constructor MkNvidiaRuntimeCertificate
  build : ExternalModuleCertificate
  kpiMemory : Measurement KpiMemory
  pciDeviceModel : Measurement PciDeviceModel
  dmaAndIommu : Measurement DmaAndIommu
  msiAndIrq : Measurement MsiAndIrq
  synchronization : Measurement Synchronization
  workqueuesAndTimers : Measurement WorkqueuesAndTimers
  deviceAndDriverModel : Measurement DeviceAndDriverModel
  drmAndKms : Measurement DrmAndKms
  firmwareLoading : Measurement FirmwareLoading
  moduleLifecycle : Measurement ModuleLifecycle

||| Runtime evidence for the first bounded Linux thread-group slice. A wake
||| certificate cannot omit clone identity, independent TLS, the blocking
||| transition, or kernel-owned clear-child-tid publication.
public export
record ThreadWakeCertificate where
  constructor MkThreadWakeCertificate
  sharedAddressSpaceClone : Measurement SharedAddressSpaceClone
  sharedDescriptorTable : Measurement SharedDescriptorTable
  distinctThreadIdentity : Measurement DistinctThreadIdentity
  perThreadTls : Measurement PerThreadTls
  privateFutexBlock : Measurement PrivateFutexBlock
  clearChildTidWake : Measurement ClearChildTidWake

||| Exit recovery extends the measured thread wake contract with exact
||| registration, owner-death publication, and wake evidence. It is therefore
||| impossible to claim robust recovery without the underlying shared-address-
||| space and blocking guarantees.
public export
record RobustExitCertificate where
  constructor MkRobustExitCertificate
  threadWake : ThreadWakeCertificate
  robustListRegistration : Measurement RobustListRegistration
  ownerDeathPublication : Measurement OwnerDeathPublication
  robustFutexWake : Measurement RobustFutexWake

||| Runtime evidence for the first bounded x86-64 signal round trip. The
||| certificate retains robust thread-exit evidence and cannot omit signal
||| disposition, mask/pending behavior, frame construction, or validated
||| rt_sigreturn.
public export
record SignalReturnCertificate where
  constructor MkSignalReturnCertificate
  robustExit : RobustExitCertificate
  signalDisposition : Measurement SignalDisposition
  signalMaskAndPending : Measurement SignalMaskAndPending
  rtSignalFrame : Measurement RtSignalFrame
  rtSignalReturn : Measurement RtSignalReturn

||| Runtime evidence that exit_group consumes one bounded exact-generation
||| snapshot, retires every non-leader TID, publishes one waitable leader
||| zombie, and is observed by the external supervisor.
public export
record GroupExitCertificate where
  constructor MkGroupExitCertificate
  signalReturn : SignalReturnCertificate
  threadGroupSnapshot : Measurement ThreadGroupSnapshot
  peerGenerationRetirement : Measurement PeerGenerationRetirement
  leaderZombiePublication : Measurement LeaderZombiePublication
  supervisorReap : Measurement SupervisorReap

||| Runtime evidence for same-PID static image replacement. The former image
||| remains the rollback target until a measured replacement has passed
||| inactive activation and both ownership registries commit. Reclamation is
||| represented only after the architecture return path changes page roots.
public export
record ExecReplacementCertificate where
  constructor MkExecReplacementCertificate
  groupExit : GroupExitCertificate
  immutableFileSnapshot : Measurement ImmutableFileSnapshot
  boundedExecVectors : Measurement BoundedExecVectors
  measuredStaticImage : Measurement MeasuredStaticImage
  inactiveActivation : Measurement InactiveActivation
  atomicImageExchange : Measurement AtomicImageExchange
  execStateReset : Measurement ExecStateReset
  deferredImageReap : Measurement DeferredImageReap
  rollbackPreservesImage : Measurement RollbackPreservesImage

||| Dynamic execution extends, rather than replaces, the same-PID static
||| replacement contract. A certificate cannot omit either immutable file,
||| either measurement, the one-hierarchy commit, the Linux auxiliary vector,
||| or the observed linker-to-main control transfer.
public export
record DynamicExecCertificate where
  constructor MkDynamicExecCertificate
  staticReplacement : ExecReplacementCertificate
  atomicExecutablePairSnapshot : Measurement AtomicExecutablePairSnapshot
  measuredRuntimeLinker : Measurement MeasuredRuntimeLinker
  compositeImageInstall : Measurement CompositeImageInstall
  linuxAuxiliaryVector : Measurement LinuxAuxiliaryVector
  runtimeLinkerEntry : Measurement RuntimeLinkerEntry
  mainEntryTransfer : Measurement MainEntryTransfer

||| Runtime qualification structurally contains build qualification.
public export
runtimeRequiresBuild : NvidiaRuntimeCertificate -> ExternalModuleCertificate
runtimeRequiresBuild certificate = certificate.build

||| Cross-thread wake qualification structurally contains the shared-address-
||| space admission evidence that makes one virtual futex address meaningful.
public export
wakeRequiresSharedAddressSpace :
  ThreadWakeCertificate -> Measurement SharedAddressSpaceClone
wakeRequiresSharedAddressSpace certificate = certificate.sharedAddressSpaceClone

||| Robust exit recovery structurally retains the complete prior thread wake
||| certificate.
public export
robustExitRequiresThreadWake : RobustExitCertificate -> ThreadWakeCertificate
robustExitRequiresThreadWake certificate = certificate.threadWake

||| Signal delivery remains structurally downstream of qualified thread exit.
public export
signalReturnRequiresRobustExit : SignalReturnCertificate -> RobustExitCertificate
signalReturnRequiresRobustExit certificate = certificate.robustExit

||| Whole-group termination remains downstream of qualified signal return.
public export
groupExitRequiresSignalReturn : GroupExitCertificate -> SignalReturnCertificate
groupExitRequiresSignalReturn certificate = certificate.signalReturn

||| Image replacement remains downstream of qualified whole-group lifecycle
||| behavior, even though the admitted first slice requires one group member.
public export
execReplacementRequiresGroupExit : ExecReplacementCertificate -> GroupExitCertificate
execReplacementRequiresGroupExit certificate = certificate.groupExit

||| Dynamic ELF entry structurally retains every transactional replacement
||| and rollback obligation already required by static execution.
public export
dynamicExecRequiresStaticReplacement :
  DynamicExecCertificate -> ExecReplacementCertificate
dynamicExecRequiresStaticReplacement certificate = certificate.staticReplacement
