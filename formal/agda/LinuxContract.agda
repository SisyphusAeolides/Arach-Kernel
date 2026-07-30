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

-- Runtime qualification can only be constructed with build qualification.
runtimeRequiresBuild : NvidiaRuntimeCertificate -> ExternalModuleCertificate
runtimeRequiresBuild certificate = NvidiaRuntimeCertificate.build certificate
