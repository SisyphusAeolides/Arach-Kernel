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
  | UnifiedDescriptorNamespace
  | GenerationBoundOpenObject
  | DescriptorAliasLifetime
  | DescriptorLocalCloseOnExec
  | PipeAtomicTransfer
  | PipeEndpointLifetime
  | PollEpollPipeReadiness
  | EpollWatchLifetime
  | ExecDescriptorInheritance
  | UnixSocketPair
  | GenerationBoundSocketEndpoint
  | UnixSocketNamespace
  | UnixSocketConnectAccept
  | UnixSocketFullDuplex
  | UnixSocketMessageVectors
  | PollEpollSocketReadiness
  | UnixSocketHalfClose
  | UnixSocketPeerIdentity
  | AncillaryRightsTransfer
  | CrossProcessOpenDescription
  | GenerationBoundMemfd
  | SharedFrameAlias
  | MappingOutlivesDescriptor
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
  | GenerationBoundDescriptorSnapshot
  | PrivateFileMapping
  | WriteXorExecuteTransition
  | MappedCodeEntry
  | NeededEntryDiscovery
  | BoundedSharedObjectSnapshot
  | RelativeRelocation
  | SharedObjectWxSeal
  | SharedSymbolCall
  | DependencyGraphClosure
  | ExternalSymbolRelocation
  | EagerPltBinding
  | CrossObjectCall
  | BoundedObjectClosure
  | BreadthFirstDiscovery
  | DuplicateDependencyCoalescing
  | AcyclicRelocationOrder
  | GlobalSymbolScope
  | DirectoryCreation
  | CanonicalRunpath
  | RunpathDependencySearch
  | StaticTlsLayout
  | TlsRelocation
  | DynamicTlsVector
  | TlsResolver
  | GeneralDynamicTlsAccess
  | InitializerOrder
  | BoundedSymbolVersionTables
  | ExactSymbolVersionResolution
  | FinalizerHandoff
  | ReverseFinalizerOrder

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

||| Runtime evidence for the unified descriptor and anonymous-pipe boundary.
||| Public descriptor reuse cannot change an epoll target, a watch follows an
||| open object while descriptor aliases remain, the last descriptor close
||| detaches it, and exec inheritance is impossible to claim without
||| independently measured close-on-exec behavior.
public export
record DescriptorPipeCertificate where
  constructor MkDescriptorPipeCertificate
  signalReturn : SignalReturnCertificate
  unifiedDescriptorNamespace : Measurement UnifiedDescriptorNamespace
  generationBoundOpenObject : Measurement GenerationBoundOpenObject
  descriptorAliasLifetime : Measurement DescriptorAliasLifetime
  descriptorLocalCloseOnExec : Measurement DescriptorLocalCloseOnExec
  pipeAtomicTransfer : Measurement PipeAtomicTransfer
  pipeEndpointLifetime : Measurement PipeEndpointLifetime
  pollEpollPipeReadiness : Measurement PollEpollPipeReadiness
  epollWatchLifetime : Measurement EpollWatchLifetime
  execDescriptorInheritance : Measurement ExecDescriptorInheritance

||| Runtime evidence for the bounded Unix-domain stream-socket boundary.
||| Socket qualification retains the complete descriptor and pipe contract,
||| then requires generation-bound endpoints, namespace and connection
||| lifecycle, data and vector transfer, readiness, half-close, and peer
||| identity observations. Scheduler-backed blocking waits remain outside this
||| certificate.
public export
record UnixSocketCertificate where
  constructor MkUnixSocketCertificate
  descriptorPipe : DescriptorPipeCertificate
  unixSocketPair : Measurement UnixSocketPair
  generationBoundSocketEndpoint : Measurement GenerationBoundSocketEndpoint
  unixSocketNamespace : Measurement UnixSocketNamespace
  unixSocketConnectAccept : Measurement UnixSocketConnectAccept
  unixSocketFullDuplex : Measurement UnixSocketFullDuplex
  unixSocketMessageVectors : Measurement UnixSocketMessageVectors
  pollEpollSocketReadiness : Measurement PollEpollSocketReadiness
  unixSocketHalfClose : Measurement UnixSocketHalfClose
  unixSocketPeerIdentity : Measurement UnixSocketPeerIdentity

||| Shared-memory qualification retains the complete local-socket boundary,
||| then requires bounded ancillary transfer, one cross-process open
||| description, generation-bound memory files, physical frame aliasing, and
||| VMA lifetime independent of the last public descriptor.
public export
record SharedMemoryCertificate where
  constructor MkSharedMemoryCertificate
  unixSocket : UnixSocketCertificate
  ancillaryRightsTransfer : Measurement AncillaryRightsTransfer
  crossProcessOpenDescription : Measurement CrossProcessOpenDescription
  generationBoundMemfd : Measurement GenerationBoundMemfd
  sharedFrameAlias : Measurement SharedFrameAlias
  mappingOutlivesDescriptor : Measurement MappingOutlivesDescriptor

||| Runtime evidence that exit_group consumes one bounded exact-generation
||| snapshot, retires every non-leader TID, publishes one waitable leader
||| zombie, and is observed by the external supervisor.
public export
record GroupExitCertificate where
  constructor MkGroupExitCertificate
  sharedMemory : SharedMemoryCertificate
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

||| Runtime file mapping remains downstream of measured dynamic entry. A
||| certificate must retain the exact descriptor-generation snapshot, private
||| frame ownership, rollback-safe W^X transition, and observed mapped entry.
public export
record FileMappingCertificate where
  constructor MkFileMappingCertificate
  dynamicExec : DynamicExecCertificate
  generationBoundDescriptorSnapshot : Measurement GenerationBoundDescriptorSnapshot
  privateFileMapping : Measurement PrivateFileMapping
  writeXorExecuteTransition : Measurement WriteXorExecuteTransition
  mappedCodeEntry : Measurement MappedCodeEntry

||| Shared-object execution remains downstream of the qualified private-file
||| mapping boundary. A certificate cannot omit dependency discovery, bounded
||| snapshot ownership, relocation, final W^X sealing, or the observed symbol
||| call that consumes relocated state.
public export
record SharedObjectCertificate where
  constructor MkSharedObjectCertificate
  fileMapping : FileMappingCertificate
  neededEntryDiscovery : Measurement NeededEntryDiscovery
  boundedSharedObjectSnapshot : Measurement BoundedSharedObjectSnapshot
  relativeRelocation : Measurement RelativeRelocation
  sharedObjectWxSeal : Measurement SharedObjectWxSeal
  sharedSymbolCall : Measurement SharedSymbolCall

||| A dependency-graph certificate extends the qualified single-object
||| boundary with exact graph closure, provider-first relocation, eager
||| external binding, and an observed call across the object boundary.
public export
record DependencyGraphCertificate where
  constructor MkDependencyGraphCertificate
  sharedObject : SharedObjectCertificate
  dependencyGraphClosure : Measurement DependencyGraphClosure
  externalSymbolRelocation : Measurement ExternalSymbolRelocation
  eagerPltBinding : Measurement EagerPltBinding
  crossObjectCall : Measurement CrossObjectCall

||| The bounded multi-object certificate retains the first cross-object
||| execution boundary and adds finite closure, deterministic breadth-first
||| discovery, one snapshot per SONAME, cycle-free provider-first ordering,
||| and deterministic process-global symbol scope.
public export
record MultiObjectGraphCertificate where
  constructor MkMultiObjectGraphCertificate
  dependencyGraph : DependencyGraphCertificate
  boundedObjectClosure : Measurement BoundedObjectClosure
  breadthFirstDiscovery : Measurement BreadthFirstDiscovery
  duplicateDependencyCoalescing : Measurement DuplicateDependencyCoalescing
  acyclicRelocationOrder : Measurement AcyclicRelocationOrder
  globalSymbolScope : Measurement GlobalSymbolScope

||| The first runtime-initialization certificate retains the complete bounded
||| object graph and adds measured directory creation, canonical bounded
||| runpaths, direct-dependency search, one finite Variant-II TLS arena,
||| checked static and general-dynamic relocations, a bounded dynamic-thread
||| vector, one exact resolver boundary, and dependency-first initialization.
public export
record RuntimeInitializationCertificate where
  constructor MkRuntimeInitializationCertificate
  multiObjectGraph : MultiObjectGraphCertificate
  directoryCreation : Measurement DirectoryCreation
  canonicalRunpath : Measurement CanonicalRunpath
  runpathDependencySearch : Measurement RunpathDependencySearch
  staticTlsLayout : Measurement StaticTlsLayout
  tlsRelocation : Measurement TlsRelocation
  dynamicTlsVector : Measurement DynamicTlsVector
  tlsResolver : Measurement TlsResolver
  generalDynamicTlsAccess : Measurement GeneralDynamicTlsAccess
  initializerOrder : Measurement InitializerOrder

||| Versioned binding and process finalization remain downstream of the
||| complete runtime-initialization boundary. The certificate requires finite
||| GNU version tables, exact version-and-provider matching, the ABI finalizer
||| handoff, and reverse dependency/array execution.
public export
record RuntimeFinalizationCertificate where
  constructor MkRuntimeFinalizationCertificate
  runtimeInitialization : RuntimeInitializationCertificate
  boundedSymbolVersionTables : Measurement BoundedSymbolVersionTables
  exactSymbolVersionResolution : Measurement ExactSymbolVersionResolution
  finalizerHandoff : Measurement FinalizerHandoff
  reverseFinalizerOrder : Measurement ReverseFinalizerOrder

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

||| Unified descriptor qualification remains downstream of signal return.
public export
descriptorPipeRequiresSignalReturn : DescriptorPipeCertificate -> SignalReturnCertificate
descriptorPipeRequiresSignalReturn certificate = certificate.signalReturn

||| Unix stream sockets remain structurally downstream of the unified
||| descriptor and pipe boundary that owns their public descriptor lifetime.
public export
unixSocketRequiresDescriptorPipe : UnixSocketCertificate -> DescriptorPipeCertificate
unixSocketRequiresDescriptorPipe certificate = certificate.descriptorPipe

||| Shared memory remains downstream of the local-socket transport carrying
||| its generation-bound open descriptions.
public export
sharedMemoryRequiresUnixSocket : SharedMemoryCertificate -> UnixSocketCertificate
sharedMemoryRequiresUnixSocket certificate = certificate.unixSocket

||| Whole-group termination remains downstream of the shared-memory boundary
||| used by service and replacement-image IPC.
public export
groupExitRequiresSharedMemory : GroupExitCertificate -> SharedMemoryCertificate
groupExitRequiresSharedMemory certificate = certificate.sharedMemory

public export
groupExitRequiresUnixSocket : GroupExitCertificate -> UnixSocketCertificate
groupExitRequiresUnixSocket certificate = certificate.sharedMemory.unixSocket

||| The complete descriptor and pipe boundary remains projectable through the
||| required Unix-socket certificate.
public export
groupExitRequiresDescriptorPipe : GroupExitCertificate -> DescriptorPipeCertificate
groupExitRequiresDescriptorPipe certificate =
  certificate.sharedMemory.unixSocket.descriptorPipe

public export
groupExitRequiresSignalReturn : GroupExitCertificate -> SignalReturnCertificate
groupExitRequiresSignalReturn certificate =
  certificate.sharedMemory.unixSocket.descriptorPipe.signalReturn

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

||| File-backed executable mappings cannot be projected without the complete
||| measured dynamic-execution contract that precedes them.
public export
fileMappingRequiresDynamicExec :
  FileMappingCertificate -> DynamicExecCertificate
fileMappingRequiresDynamicExec certificate = certificate.dynamicExec

||| Shared-object relocation cannot be projected without the complete private
||| file-mapping and protection contract used to stage and seal every segment.
public export
sharedObjectRequiresFileMapping :
  SharedObjectCertificate -> FileMappingCertificate
sharedObjectRequiresFileMapping certificate = certificate.fileMapping

||| Cross-object binding cannot be projected without the complete prior
||| shared-object snapshot, relocation, sealing, and execution contract.
public export
dependencyGraphRequiresSharedObject :
  DependencyGraphCertificate -> SharedObjectCertificate
dependencyGraphRequiresSharedObject certificate = certificate.sharedObject

||| General bounded closure cannot be projected without the earlier measured
||| dependency, relocation, eager-binding, and cross-object call evidence.
public export
multiObjectGraphRequiresDependencyGraph :
  MultiObjectGraphCertificate -> DependencyGraphCertificate
multiObjectGraphRequiresDependencyGraph certificate = certificate.dependencyGraph

||| Search-path, TLS, and initializer qualification cannot be projected without
||| the complete dependency graph, relocation, sealing, and global-scope
||| evidence.
public export
runtimeInitializationRequiresMultiObjectGraph :
  RuntimeInitializationCertificate -> MultiObjectGraphCertificate
runtimeInitializationRequiresMultiObjectGraph certificate =
  certificate.multiObjectGraph

||| Finalization and exact version binding cannot be projected without the
||| complete startup-TLS, relocation, resolver, and initializer certificate.
public export
runtimeFinalizationRequiresInitialization :
  RuntimeFinalizationCertificate -> RuntimeInitializationCertificate
runtimeFinalizationRequiresInitialization certificate =
  certificate.runtimeInitialization
