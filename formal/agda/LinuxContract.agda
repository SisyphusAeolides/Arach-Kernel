{-# OPTIONS --safe --without-K #-}
module LinuxContract where

open import Agda.Builtin.List using (List)
open import Agda.Builtin.String using (String)

data Gate : Set where
  externalKbuild generatedConfiguration symbolVersions modpost : Gate
  moduleLinkerScripts linuxHeaders linuxModuleElf kpiMemory : Gate
  pciDeviceModel dmaAndIommu msiAndIrq synchronization : Gate
  workqueuesAndTimers deviceAndDriverModel drmAndKms : Gate
  firmwareLoading moduleLifecycle : Gate
  sharedAddressSpaceClone sharedDescriptorTable distinctThreadIdentity perThreadTls : Gate
  privateFutexBlock clearChildTidWake : Gate
  robustListRegistration ownerDeathPublication robustFutexWake : Gate
  signalDisposition signalMaskAndPending rtSignalFrame rtSignalReturn : Gate
  threadGroupSnapshot peerGenerationRetirement leaderZombiePublication supervisorReap : Gate

-- firstPassingCase makes an empty test result unrepresentable.
record Measurement (gate : Gate) : Set where
  constructor measurement
  field
    suite firstPassingCase artifactDigest : String
    additionalPassingCases : List String

record ExternalModuleCertificate : Set where
  constructor externalModuleCertificate
  field
    externalKbuildEvidence : Measurement externalKbuild
    generatedConfigurationEvidence : Measurement generatedConfiguration
    symbolVersionsEvidence : Measurement symbolVersions
    modpostEvidence : Measurement modpost
    moduleLinkerScriptsEvidence : Measurement moduleLinkerScripts
    linuxHeadersEvidence : Measurement linuxHeaders
    linuxModuleElfEvidence : Measurement linuxModuleElf

record NvidiaRuntimeCertificate : Set where
  constructor nvidiaRuntimeCertificate
  field
    build : ExternalModuleCertificate
    kpiMemoryEvidence : Measurement kpiMemory
    pciDeviceModelEvidence : Measurement pciDeviceModel
    dmaAndIommuEvidence : Measurement dmaAndIommu
    msiAndIrqEvidence : Measurement msiAndIrq
    synchronizationEvidence : Measurement synchronization
    workqueuesAndTimersEvidence : Measurement workqueuesAndTimers
    deviceAndDriverModelEvidence : Measurement deviceAndDriverModel
    drmAndKmsEvidence : Measurement drmAndKms
    firmwareLoadingEvidence : Measurement firmwareLoading
    moduleLifecycleEvidence : Measurement moduleLifecycle

record ThreadWakeCertificate : Set where
  constructor threadWakeCertificate
  field
    sharedAddressSpaceCloneEvidence : Measurement sharedAddressSpaceClone
    sharedDescriptorTableEvidence : Measurement sharedDescriptorTable
    distinctThreadIdentityEvidence : Measurement distinctThreadIdentity
    perThreadTlsEvidence : Measurement perThreadTls
    privateFutexBlockEvidence : Measurement privateFutexBlock
    clearChildTidWakeEvidence : Measurement clearChildTidWake

record RobustExitCertificate : Set where
  constructor robustExitCertificate
  field
    threadWake : ThreadWakeCertificate
    robustListRegistrationEvidence : Measurement robustListRegistration
    ownerDeathPublicationEvidence : Measurement ownerDeathPublication
    robustFutexWakeEvidence : Measurement robustFutexWake

record SignalReturnCertificate : Set where
  constructor signalReturnCertificate
  field
    robustExit : RobustExitCertificate
    signalDispositionEvidence : Measurement signalDisposition
    signalMaskAndPendingEvidence : Measurement signalMaskAndPending
    rtSignalFrameEvidence : Measurement rtSignalFrame
    rtSignalReturnEvidence : Measurement rtSignalReturn

record GroupExitCertificate : Set where
  constructor groupExitCertificate
  field
    signalReturn : SignalReturnCertificate
    threadGroupSnapshotEvidence : Measurement threadGroupSnapshot
    peerGenerationRetirementEvidence : Measurement peerGenerationRetirement
    leaderZombiePublicationEvidence : Measurement leaderZombiePublication
    supervisorReapEvidence : Measurement supervisorReap

-- Runtime qualification can only be constructed with build qualification.
runtimeRequiresBuild : NvidiaRuntimeCertificate -> ExternalModuleCertificate
runtimeRequiresBuild certificate = NvidiaRuntimeCertificate.build certificate

-- Futex wake qualification cannot be projected without the measured clone
-- evidence that gives both tasks the same address-space identity.
wakeRequiresSharedAddressSpace :
  ThreadWakeCertificate -> Measurement sharedAddressSpaceClone
wakeRequiresSharedAddressSpace certificate =
  ThreadWakeCertificate.sharedAddressSpaceCloneEvidence certificate

-- Robust recovery cannot be projected without the prior clone, identity,
-- blocking, and clear-child-tid wake evidence.
robustExitRequiresThreadWake : RobustExitCertificate -> ThreadWakeCertificate
robustExitRequiresThreadWake certificate = RobustExitCertificate.threadWake certificate

-- Signal return qualification structurally retains robust thread-exit
-- qualification.
signalReturnRequiresRobustExit : SignalReturnCertificate -> RobustExitCertificate
signalReturnRequiresRobustExit certificate = SignalReturnCertificate.robustExit certificate

-- Whole-group termination structurally retains qualified signal return.
groupExitRequiresSignalReturn : GroupExitCertificate -> SignalReturnCertificate
groupExitRequiresSignalReturn certificate = GroupExitCertificate.signalReturn certificate
