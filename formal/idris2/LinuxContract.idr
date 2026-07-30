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

||| Runtime qualification structurally contains build qualification.
public export
runtimeRequiresBuild : NvidiaRuntimeCertificate -> ExternalModuleCertificate
runtimeRequiresBuild certificate = certificate.build
