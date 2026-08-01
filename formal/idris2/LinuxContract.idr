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
