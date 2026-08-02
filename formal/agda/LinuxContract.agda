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
  unifiedDescriptorNamespace generationBoundOpenObject : Gate
  descriptorAliasLifetime descriptorLocalCloseOnExec : Gate
  pipeAtomicTransfer pipeEndpointLifetime pollEpollPipeReadiness : Gate
  epollWatchLifetime execDescriptorInheritance : Gate
  unixSocketPair generationBoundSocketEndpoint unixSocketNamespace : Gate
  unixSocketConnectAccept unixSocketFullDuplex unixSocketMessageVectors : Gate
  pollEpollSocketReadiness unixSocketHalfClose unixSocketPeerIdentity : Gate
  ancillaryRightsTransfer crossProcessOpenDescription generationBoundMemfd : Gate
  sharedFrameAlias mappingOutlivesDescriptor : Gate
  threadGroupSnapshot peerGenerationRetirement leaderZombiePublication supervisorReap : Gate
  immutableFileSnapshot boundedExecVectors measuredStaticImage inactiveActivation : Gate
  atomicImageExchange execStateReset deferredImageReap rollbackPreservesImage : Gate
  atomicExecutablePairSnapshot measuredRuntimeLinker compositeImageInstall : Gate
  linuxAuxiliaryVector runtimeLinkerEntry mainEntryTransfer : Gate
  generationBoundDescriptorSnapshot privateFileMapping : Gate
  writeXorExecuteTransition mappedCodeEntry : Gate
  neededEntryDiscovery boundedSharedObjectSnapshot relativeRelocation : Gate
  sharedObjectWxSeal sharedSymbolCall : Gate
  dependencyGraphClosure externalSymbolRelocation eagerPltBinding : Gate
  crossObjectCall : Gate
  boundedObjectClosure breadthFirstDiscovery : Gate
  duplicateDependencyCoalescing acyclicRelocationOrder globalSymbolScope : Gate
  firstDefinitionWeakBinding unresolvedWeakZero : Gate
  globalDataRelocation firstDefinitionWeakDataBinding : Gate
  unresolvedWeakDataZero : Gate
  absoluteSymbolRelocation boundedAbsoluteSymbolAddend : Gate
  firstDefinitionWeakAbsoluteBinding unresolvedWeakAbsoluteZero : Gate
  packedRelativeRelocation boundedPackedRelativeDecoding : Gate
  canonicalPackedRelativeOrder disjointPackedRelativeTargets : Gate
  immutablePackedRelativeTable : Gate
  boundedMainExecutableSnapshot mainCopyRelocation exactCopyExtent : Gate
  disjointCopyTargets disjointCopySource prevalidatedCopyBatch : Gate
  mainExecutableInterposition : Gate
  directoryCreation canonicalRunpath runpathDependencySearch : Gate
  staticTlsLayout tlsRelocation dynamicTlsVector tlsResolver : Gate
  generalDynamicTlsAccess initializerOrder : Gate
  boundedSymbolVersionTables exactSymbolVersionResolution : Gate
  finalizerHandoff reverseFinalizerOrder : Gate

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

record DescriptorPipeCertificate : Set where
  constructor descriptorPipeCertificate
  field
    signalReturn : SignalReturnCertificate
    unifiedDescriptorNamespaceEvidence : Measurement unifiedDescriptorNamespace
    generationBoundOpenObjectEvidence : Measurement generationBoundOpenObject
    descriptorAliasLifetimeEvidence : Measurement descriptorAliasLifetime
    descriptorLocalCloseOnExecEvidence : Measurement descriptorLocalCloseOnExec
    pipeAtomicTransferEvidence : Measurement pipeAtomicTransfer
    pipeEndpointLifetimeEvidence : Measurement pipeEndpointLifetime
    pollEpollPipeReadinessEvidence : Measurement pollEpollPipeReadiness
    epollWatchLifetimeEvidence : Measurement epollWatchLifetime
    execDescriptorInheritanceEvidence : Measurement execDescriptorInheritance

record UnixSocketCertificate : Set where
  constructor unixSocketCertificate
  field
    descriptorPipe : DescriptorPipeCertificate
    unixSocketPairEvidence : Measurement unixSocketPair
    generationBoundSocketEndpointEvidence : Measurement generationBoundSocketEndpoint
    unixSocketNamespaceEvidence : Measurement unixSocketNamespace
    unixSocketConnectAcceptEvidence : Measurement unixSocketConnectAccept
    unixSocketFullDuplexEvidence : Measurement unixSocketFullDuplex
    unixSocketMessageVectorsEvidence : Measurement unixSocketMessageVectors
    pollEpollSocketReadinessEvidence : Measurement pollEpollSocketReadiness
    unixSocketHalfCloseEvidence : Measurement unixSocketHalfClose
    unixSocketPeerIdentityEvidence : Measurement unixSocketPeerIdentity

record SharedMemoryCertificate : Set where
  constructor sharedMemoryCertificate
  field
    unixSocket : UnixSocketCertificate
    ancillaryRightsTransferEvidence : Measurement ancillaryRightsTransfer
    crossProcessOpenDescriptionEvidence : Measurement crossProcessOpenDescription
    generationBoundMemfdEvidence : Measurement generationBoundMemfd
    sharedFrameAliasEvidence : Measurement sharedFrameAlias
    mappingOutlivesDescriptorEvidence : Measurement mappingOutlivesDescriptor

record GroupExitCertificate : Set where
  constructor groupExitCertificate
  field
    sharedMemory : SharedMemoryCertificate
    threadGroupSnapshotEvidence : Measurement threadGroupSnapshot
    peerGenerationRetirementEvidence : Measurement peerGenerationRetirement
    leaderZombiePublicationEvidence : Measurement leaderZombiePublication
    supervisorReapEvidence : Measurement supervisorReap

record ExecReplacementCertificate : Set where
  constructor execReplacementCertificate
  field
    groupExit : GroupExitCertificate
    immutableFileSnapshotEvidence : Measurement immutableFileSnapshot
    boundedExecVectorsEvidence : Measurement boundedExecVectors
    measuredStaticImageEvidence : Measurement measuredStaticImage
    inactiveActivationEvidence : Measurement inactiveActivation
    atomicImageExchangeEvidence : Measurement atomicImageExchange
    execStateResetEvidence : Measurement execStateReset
    deferredImageReapEvidence : Measurement deferredImageReap
    rollbackPreservesImageEvidence : Measurement rollbackPreservesImage

record DynamicExecCertificate : Set where
  constructor dynamicExecCertificate
  field
    staticReplacement : ExecReplacementCertificate
    atomicExecutablePairSnapshotEvidence : Measurement atomicExecutablePairSnapshot
    measuredRuntimeLinkerEvidence : Measurement measuredRuntimeLinker
    compositeImageInstallEvidence : Measurement compositeImageInstall
    linuxAuxiliaryVectorEvidence : Measurement linuxAuxiliaryVector
    runtimeLinkerEntryEvidence : Measurement runtimeLinkerEntry
    mainEntryTransferEvidence : Measurement mainEntryTransfer

record FileMappingCertificate : Set where
  constructor fileMappingCertificate
  field
    dynamicExec : DynamicExecCertificate
    generationBoundDescriptorSnapshotEvidence : Measurement generationBoundDescriptorSnapshot
    privateFileMappingEvidence : Measurement privateFileMapping
    writeXorExecuteTransitionEvidence : Measurement writeXorExecuteTransition
    mappedCodeEntryEvidence : Measurement mappedCodeEntry

record SharedObjectCertificate : Set where
  constructor sharedObjectCertificate
  field
    fileMapping : FileMappingCertificate
    neededEntryDiscoveryEvidence : Measurement neededEntryDiscovery
    boundedSharedObjectSnapshotEvidence : Measurement boundedSharedObjectSnapshot
    relativeRelocationEvidence : Measurement relativeRelocation
    sharedObjectWxSealEvidence : Measurement sharedObjectWxSeal
    sharedSymbolCallEvidence : Measurement sharedSymbolCall

record DependencyGraphCertificate : Set where
  constructor dependencyGraphCertificate
  field
    sharedObject : SharedObjectCertificate
    dependencyGraphClosureEvidence : Measurement dependencyGraphClosure
    externalSymbolRelocationEvidence : Measurement externalSymbolRelocation
    eagerPltBindingEvidence : Measurement eagerPltBinding
    crossObjectCallEvidence : Measurement crossObjectCall

record MultiObjectGraphCertificate : Set where
  constructor multiObjectGraphCertificate
  field
    dependencyGraph : DependencyGraphCertificate
    boundedObjectClosureEvidence : Measurement boundedObjectClosure
    breadthFirstDiscoveryEvidence : Measurement breadthFirstDiscovery
    duplicateDependencyCoalescingEvidence : Measurement duplicateDependencyCoalescing
    acyclicRelocationOrderEvidence : Measurement acyclicRelocationOrder
    globalSymbolScopeEvidence : Measurement globalSymbolScope

record RuntimeInitializationCertificate : Set where
  constructor runtimeInitializationCertificate
  field
    multiObjectGraph : MultiObjectGraphCertificate
    directoryCreationEvidence : Measurement directoryCreation
    canonicalRunpathEvidence : Measurement canonicalRunpath
    runpathDependencySearchEvidence : Measurement runpathDependencySearch
    firstDefinitionWeakBindingEvidence : Measurement firstDefinitionWeakBinding
    unresolvedWeakZeroEvidence : Measurement unresolvedWeakZero
    globalDataRelocationEvidence : Measurement globalDataRelocation
    firstDefinitionWeakDataBindingEvidence :
      Measurement firstDefinitionWeakDataBinding
    unresolvedWeakDataZeroEvidence : Measurement unresolvedWeakDataZero
    absoluteSymbolRelocationEvidence : Measurement absoluteSymbolRelocation
    boundedAbsoluteSymbolAddendEvidence :
      Measurement boundedAbsoluteSymbolAddend
    firstDefinitionWeakAbsoluteBindingEvidence :
      Measurement firstDefinitionWeakAbsoluteBinding
    unresolvedWeakAbsoluteZeroEvidence :
      Measurement unresolvedWeakAbsoluteZero
    packedRelativeRelocationEvidence : Measurement packedRelativeRelocation
    boundedPackedRelativeDecodingEvidence :
      Measurement boundedPackedRelativeDecoding
    canonicalPackedRelativeOrderEvidence :
      Measurement canonicalPackedRelativeOrder
    disjointPackedRelativeTargetsEvidence :
      Measurement disjointPackedRelativeTargets
    immutablePackedRelativeTableEvidence :
      Measurement immutablePackedRelativeTable
    boundedMainExecutableSnapshotEvidence :
      Measurement boundedMainExecutableSnapshot
    mainCopyRelocationEvidence : Measurement mainCopyRelocation
    exactCopyExtentEvidence : Measurement exactCopyExtent
    disjointCopyTargetsEvidence : Measurement disjointCopyTargets
    disjointCopySourceEvidence : Measurement disjointCopySource
    prevalidatedCopyBatchEvidence : Measurement prevalidatedCopyBatch
    mainExecutableInterpositionEvidence :
      Measurement mainExecutableInterposition
    staticTlsLayoutEvidence : Measurement staticTlsLayout
    tlsRelocationEvidence : Measurement tlsRelocation
    dynamicTlsVectorEvidence : Measurement dynamicTlsVector
    tlsResolverEvidence : Measurement tlsResolver
    generalDynamicTlsAccessEvidence : Measurement generalDynamicTlsAccess
    initializerOrderEvidence : Measurement initializerOrder

record RuntimeFinalizationCertificate : Set where
  constructor runtimeFinalizationCertificate
  field
    runtimeInitialization : RuntimeInitializationCertificate
    boundedSymbolVersionTablesEvidence : Measurement boundedSymbolVersionTables
    exactSymbolVersionResolutionEvidence : Measurement exactSymbolVersionResolution
    finalizerHandoffEvidence : Measurement finalizerHandoff
    reverseFinalizerOrderEvidence : Measurement reverseFinalizerOrder

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

-- Descriptor and pipe qualification structurally retains signal return.
descriptorPipeRequiresSignalReturn :
  DescriptorPipeCertificate -> SignalReturnCertificate
descriptorPipeRequiresSignalReturn certificate =
  DescriptorPipeCertificate.signalReturn certificate

-- Unix stream sockets structurally retain the unified descriptor and pipe
-- boundary that owns their public descriptor lifetime.
unixSocketRequiresDescriptorPipe :
  UnixSocketCertificate -> DescriptorPipeCertificate
unixSocketRequiresDescriptorPipe certificate =
  UnixSocketCertificate.descriptorPipe certificate

-- Shared-memory qualification structurally retains the local-socket transport
-- carrying its generation-bound open descriptions.
sharedMemoryRequiresUnixSocket :
  SharedMemoryCertificate -> UnixSocketCertificate
sharedMemoryRequiresUnixSocket certificate =
  SharedMemoryCertificate.unixSocket certificate

-- Whole-group termination structurally retains the shared-memory boundary
-- used by service and replacement-image IPC.
groupExitRequiresSharedMemory :
  GroupExitCertificate -> SharedMemoryCertificate
groupExitRequiresSharedMemory certificate =
  GroupExitCertificate.sharedMemory certificate

groupExitRequiresUnixSocket :
  GroupExitCertificate -> UnixSocketCertificate
groupExitRequiresUnixSocket certificate =
  SharedMemoryCertificate.unixSocket
    (GroupExitCertificate.sharedMemory certificate)

-- The descriptor and pipe boundary remains projectable through the required
-- Unix-socket certificate.
groupExitRequiresDescriptorPipe :
  GroupExitCertificate -> DescriptorPipeCertificate
groupExitRequiresDescriptorPipe certificate =
  UnixSocketCertificate.descriptorPipe
    (SharedMemoryCertificate.unixSocket
      (GroupExitCertificate.sharedMemory certificate))

-- The prior signal qualification remains projectable through that boundary.
groupExitRequiresSignalReturn : GroupExitCertificate -> SignalReturnCertificate
groupExitRequiresSignalReturn certificate =
  DescriptorPipeCertificate.signalReturn
    (UnixSocketCertificate.descriptorPipe
      (SharedMemoryCertificate.unixSocket
        (GroupExitCertificate.sharedMemory certificate)))

-- Image replacement cannot be projected without the prior group-lifecycle
-- qualification on which its single-threaded admission rule depends.
execReplacementRequiresGroupExit : ExecReplacementCertificate -> GroupExitCertificate
execReplacementRequiresGroupExit certificate =
  ExecReplacementCertificate.groupExit certificate

-- Dynamic execution cannot be projected without all prior transactional
-- replacement, rollback, process-state, and lifecycle evidence.
dynamicExecRequiresStaticReplacement :
  DynamicExecCertificate -> ExecReplacementCertificate
dynamicExecRequiresStaticReplacement certificate =
  DynamicExecCertificate.staticReplacement certificate

-- File mapping qualification structurally retains the measured dynamic-entry
-- contract on which its process image and runtime root depend.
fileMappingRequiresDynamicExec :
  FileMappingCertificate -> DynamicExecCertificate
fileMappingRequiresDynamicExec certificate =
  FileMappingCertificate.dynamicExec certificate

-- Shared-object relocation structurally retains the qualified private-file
-- mapping and W^X transition boundary used by every admitted segment.
sharedObjectRequiresFileMapping :
  SharedObjectCertificate -> FileMappingCertificate
sharedObjectRequiresFileMapping certificate =
  SharedObjectCertificate.fileMapping certificate

-- Cross-object binding structurally retains the qualified shared-object
-- snapshot, relocation, sealing, and execution boundary.
dependencyGraphRequiresSharedObject :
  DependencyGraphCertificate -> SharedObjectCertificate
dependencyGraphRequiresSharedObject certificate =
  DependencyGraphCertificate.sharedObject certificate

-- Multi-object closure structurally retains the first measured dependency
-- graph, relocation, eager-binding, and cross-object call boundary.
multiObjectGraphRequiresDependencyGraph :
  MultiObjectGraphCertificate -> DependencyGraphCertificate
multiObjectGraphRequiresDependencyGraph certificate =
  MultiObjectGraphCertificate.dependencyGraph certificate

-- Runtime initialization structurally retains bounded closure, provider-first
-- relocation, and deterministic process-global symbol scope before adding
-- directory, runpath, weak-function/data, eager global-data, checked
-- absolute-symbol relocation, bounded packed-relative decoding, TLS,
-- resolver, and initializer evidence.
runtimeInitializationRequiresMultiObjectGraph :
  RuntimeInitializationCertificate -> MultiObjectGraphCertificate
runtimeInitializationRequiresMultiObjectGraph certificate =
  RuntimeInitializationCertificate.multiObjectGraph certificate

-- Finalization and version binding structurally retain the complete bounded
-- startup-TLS, resolver, and runtime-initialization certificate.
runtimeFinalizationRequiresInitialization :
  RuntimeFinalizationCertificate -> RuntimeInitializationCertificate
runtimeFinalizationRequiresInitialization certificate =
  RuntimeFinalizationCertificate.runtimeInitialization certificate
