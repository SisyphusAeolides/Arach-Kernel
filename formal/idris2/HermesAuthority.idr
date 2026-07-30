module HermesAuthority

%default total

||| Hermes phase lattice. Online is only reachable after every measured gate
||| has fired; there is no constructor that jumps from Probe to Online.
public export
data HermesPhase
  = Offline
  | Probed
  | Firmwared
  | Queued
  | Negotiated
  | Online
  | Recovering
  | Quarantined

public export
data IsTrue : Bool -> Type where
  Proven : IsTrue True

public export
data NonZero : Nat -> Type where
  IsSuccessor : NonZero (S value)

||| Raw hardware/firmware evidence collected before any authority is granted.
public export
record RawHermesEvidence where
  constructor MkRawHermesEvidence
  pciMatched : Bool
  firmwareMeasured : Bool
  iommuIsolated : Bool
  dmaDomain : Nat
  wprLocked : Bool
  bootMailboxOk : Bool
  readyQueueObserved : Bool
  negotiatedFeatures : Nat

||| Certificate that every Online gate holds for one requester generation.
public export
record OnlineCertificate (generation : Nat) where
  constructor MkOnlineCertificate
  generationIndex : Nat
  generationAgreement : generation = generationIndex
  dmaDomain : Nat
  liveDomain : NonZero dmaDomain
  pciProof : IsTrue True
  firmwareProof : IsTrue True
  iommuProof : IsTrue True
  wprProof : IsTrue True
  mailboxProof : IsTrue True
  readyProof : IsTrue True
  negotiatedFeatures : Nat
  featuresProof : NonZero negotiatedFeatures

public export
data HermesFault
  = PciMismatch
  | FirmwareUnmeasured
  | IommuMissing
  | DomainMissing
  | WprUnlocked
  | BootMailboxFailed
  | ReadyQueueSilent
  | FeatureNegotiationEmpty

public export
data HermesDecision : Nat -> Type where
  HermesRejected : HermesFault -> HermesDecision generation
  HermesAccepted : OnlineCertificate generation -> HermesDecision generation

verifyMatched :
  (generation : Nat) ->
  (domain : Nat) ->
  (pci : Bool) ->
  (firmware : Bool) ->
  (iommu : Bool) ->
  (wpr : Bool) ->
  (mailbox : Bool) ->
  (ready : Bool) ->
  (features : Nat) ->
  HermesDecision generation
verifyMatched generation Z pci firmware iommu wpr mailbox ready features =
  HermesRejected DomainMissing
verifyMatched generation (S domain) False firmware iommu wpr mailbox ready features =
  HermesRejected PciMismatch
verifyMatched generation (S domain) True False iommu wpr mailbox ready features =
  HermesRejected FirmwareUnmeasured
verifyMatched generation (S domain) True True False wpr mailbox ready features =
  HermesRejected IommuMissing
verifyMatched generation (S domain) True True True False mailbox ready features =
  HermesRejected WprUnlocked
verifyMatched generation (S domain) True True True True False ready features =
  HermesRejected BootMailboxFailed
verifyMatched generation (S domain) True True True True True False features =
  HermesRejected ReadyQueueSilent
verifyMatched generation (S domain) True True True True True True Z =
  HermesRejected FeatureNegotiationEmpty
verifyMatched generation (S domain) True True True True True True (S features) =
  HermesAccepted
    (MkOnlineCertificate
      generation
      Refl
      (S domain)
      IsSuccessor
      Proven
      Proven
      Proven
      Proven
      Proven
      Proven
      (S features)
      IsSuccessor)

public export
verifyOnline : (generation : Nat) -> RawHermesEvidence -> HermesDecision generation
verifyOnline generation
  (MkRawHermesEvidence pci firmware iommu domain wpr mailbox ready features) =
    verifyMatched generation domain pci firmware iommu wpr mailbox ready features

public export
data HermesService : HermesPhase -> Nat -> Type where
  Dark : HermesService Offline generation
  Seen : HermesService Probed generation
  ImageBound : HermesService Firmwared generation
  RingsArmed : HermesService Queued generation
  WireLive : HermesService Negotiated generation
  Serving : OnlineCertificate generation -> HermesService Online generation
  Healing : OnlineCertificate generation -> HermesService Recovering generation
  Contained : OnlineCertificate generation -> HermesService Quarantined generation

public export
data HermesTransition : HermesPhase -> HermesPhase -> Nat -> Type where
  Probe : HermesTransition Offline Probed generation
  MeasureFirmware : HermesTransition Probed Firmwared generation
  ArmQueues : HermesTransition Firmwared Queued generation
  Negotiate : HermesTransition Queued Negotiated generation
  Ignite : OnlineCertificate generation -> HermesTransition Negotiated Online generation
  DetectFault : HermesTransition Online Recovering generation
  Contain : HermesTransition Recovering Quarantined generation
  Restore : HermesTransition Recovering Online generation
  Release : HermesTransition Quarantined Offline generation

public export
advanceHermes :
  HermesService before generation ->
  HermesTransition before after generation ->
  HermesService after generation
advanceHermes Dark Probe = Seen
advanceHermes Seen MeasureFirmware = ImageBound
advanceHermes ImageBound ArmQueues = RingsArmed
advanceHermes RingsArmed Negotiate = WireLive
advanceHermes WireLive (Ignite certificate) = Serving certificate
advanceHermes (Serving certificate) DetectFault = Healing certificate
advanceHermes (Healing certificate) Contain = Contained certificate
advanceHermes (Healing certificate) Restore = Serving certificate
advanceHermes (Contained certificate) Release = Dark

public export
igniteObserved :
  {generation : Nat} ->
  HermesService Negotiated generation ->
  RawHermesEvidence ->
  Either HermesFault (HermesService Online generation)
igniteObserved {generation} WireLive observation =
  case verifyOnline generation observation of
    HermesRejected fault => Left fault
    HermesAccepted certificate =>
      Right (advanceHermes WireLive (Ignite certificate))

public export
sampleOnline : HermesDecision 7
sampleOnline =
  verifyOnline 7
    (MkRawHermesEvidence True True True 3 True True True 15)

public export
sampleOnlineAccepted : Bool
sampleOnlineAccepted =
  case sampleOnline of
    HermesRejected fault => False
    HermesAccepted certificate => True

public export
missingDomainRejects :
  verifyOnline 1 (MkRawHermesEvidence True True True 0 True True True 1)
    = HermesRejected DomainMissing
missingDomainRejects = Refl

public export
emptyFeaturesReject :
  verifyOnline 1 (MkRawHermesEvidence True True True 1 True True True 0)
    = HermesRejected FeatureNegotiationEmpty
emptyFeaturesReject = Refl

public export
probeDoesNotGrantOnline :
  advanceHermes Dark Probe = Seen
probeDoesNotGrantOnline = Refl

public export
fullGateChainServes : Bool
fullGateChainServes =
  case igniteObserved {generation = 2} WireLive
         (MkRawHermesEvidence True True True 2 True True True 4) of
    Left fault => False
    Right service => True
