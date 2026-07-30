{-# OPTIONS --safe --without-K #-}

module ArgusLayout where

data Empty : Set where

Not : Set -> Set
Not proposition = proposition -> Empty

data Nat : Set where
  zero : Nat
  suc : Nat -> Nat

-- An index is constructible only when the backing capacity is nonzero. This
-- is the spatial foundation for Argus's fixed node and text buffers.
data Index : Nat -> Set where
  first : {n : Nat} -> Index (suc n)
  next : {n : Nat} -> Index n -> Index (suc n)

noIndexInEmpty : Not (Index zero)
noIndexInEmpty ()

data Span : Nat -> Set where
  emptySpan : {capacity : Nat} -> Span capacity
  oneByte : {capacity : Nat} -> Index capacity -> Span capacity

-- Text is admitted only through a concrete in-capacity index; there is no
-- constructor for an unbounded or external address.
emptyCapacityHasNoByteSpan : Not (Span zero -> Index zero)
emptyCapacityHasNoByteSpan f with f emptySpan
... | ()

boundedFirstByte : Index (suc zero)
boundedFirstByte = first

-- External navigation is represented separately from raw transport. There is
-- no authorization constructor for scripts, and HTTPS becomes admissible only
-- under the brokered policy.
data NavigationPolicy : Set where
  measuredOnly : NavigationPolicy
  brokeredHttps : NavigationPolicy

data HypermediaTarget : Set where
  measuredDocument : HypermediaTarget
  httpsDocument : HypermediaTarget
  scriptDocument : HypermediaTarget

data Authorized : NavigationPolicy -> HypermediaTarget -> Set where
  measured : {policy : NavigationPolicy} -> Authorized policy measuredDocument
  httpsLease : Authorized brokeredHttps httpsDocument

scriptHasNoAuthority : {policy : NavigationPolicy} -> Authorized policy scriptDocument -> Empty
scriptHasNoAuthority ()

measuredPolicyCannotAuthorizeHttps : Authorized measuredOnly httpsDocument -> Empty
measuredPolicyCannotAuthorizeHttps ()

-- The broker accepts a positive, finite segment budget only with a yield
-- witness. This models the safe point required between bounded TLS/TCP work
-- slices; it deliberately makes no claim that a TLS implementation exists.
data YieldWitness : Nat -> Set where
  yieldAfterPositiveSlice : {n : Nat} -> YieldWitness (suc n)

positiveSliceYields : YieldWitness (suc (suc zero))
positiveSliceYields = yieldAfterPositiveSlice
