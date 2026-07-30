{-# OPTIONS --safe --without-K #-}

module HermesWire where

data Empty : Set where

Not : Set -> Set
Not proposition = proposition -> Empty

data Nat : Set where
  zero : Nat
  suc : Nat -> Nat

data _≡_ {A : Set} (x : A) : A -> Set where
  refl : x ≡ x

-- A ring slot exists only when the depth is positive. Hermes never constructs
-- a command or event index over a zero-depth transport profile.
data Slot : Nat -> Set where
  head : {n : Nat} -> Slot (suc n)
  tail : {n : Nat} -> Slot n -> Slot (suc n)

noSlotInEmptyRing : Not (Slot zero)
noSlotInEmptyRing ()

-- Feature bits are admitted only as a finite lattice. Display offload cannot
-- be claimed without a command ring, and compute cannot be claimed without
-- memory management.
data Feature : Set where
  bootRpc : Feature
  commandRing : Feature
  eventRing : Feature
  recovery : Feature
  display : Feature
  compute : Feature
  copyEngine : Feature
  telemetry : Feature
  power : Feature
  memoryManagement : Feature

data FeatureSet : Set where
  none : FeatureSet
  add : Feature -> FeatureSet -> FeatureSet

data Member : Feature -> FeatureSet -> Set where
  here : {feature : Feature} {rest : FeatureSet} -> Member feature (add feature rest)
  there : {feature other : Feature} {rest : FeatureSet} ->
    Member feature rest -> Member feature (add other rest)

data WellFormed : FeatureSet -> Set where
  emptyOk : WellFormed none
  bootOnly : WellFormed (add bootRpc none)
  rings :
    {rest : FeatureSet} ->
    Member bootRpc rest ->
    WellFormed (add commandRing (add eventRing rest))
  displayNeedsCommand :
    {rest : FeatureSet} ->
    Member commandRing rest ->
    WellFormed (add display rest)
  computeNeedsMemory :
    {rest : FeatureSet} ->
    Member memoryManagement rest ->
    WellFormed (add compute rest)
  powerNeedsTelemetry :
    {rest : FeatureSet} ->
    Member telemetry rest ->
    WellFormed (add power rest)

-- Wire profile capacity is a pair of positive depths. A negotiated profile
-- cannot exist without both rings.
data WireProfile : Nat -> Nat -> Set where
  profile :
    {commandDepth eventDepth : Nat} ->
    Slot (suc commandDepth) ->
    Slot (suc eventDepth) ->
    FeatureSet ->
    WireProfile (suc commandDepth) (suc eventDepth)

zeroCommandDepthForbidden :
  {eventDepth : Nat} -> Not (WireProfile zero (suc eventDepth))
zeroCommandDepthForbidden ()

zeroEventDepthForbidden :
  {commandDepth : Nat} -> Not (WireProfile (suc commandDepth) zero)
zeroEventDepthForbidden ()

-- Online publication requires a profile and a non-empty feature set that at
-- least carries the boot RPC gate. There is no Online constructor for an
-- empty feature lattice.
data OnlinePublication : Set where
  publish :
    {commandDepth eventDepth : Nat} ->
    WireProfile (suc commandDepth) (suc eventDepth) ->
    {features : FeatureSet} ->
    Member bootRpc features ->
    OnlinePublication

emptyFeaturesCannotPublish :
  {commandDepth eventDepth : Nat} ->
  {profile : WireProfile (suc commandDepth) (suc eventDepth)} ->
  Not (Member bootRpc none)
emptyFeaturesCannotPublish ()

sampleProfile : WireProfile (suc zero) (suc zero)
sampleProfile = profile head head (add bootRpc none)

sampleFeatures : FeatureSet
sampleFeatures = add bootRpc none

sampleOnline : OnlinePublication
sampleOnline = publish sampleProfile {features = sampleFeatures} here
