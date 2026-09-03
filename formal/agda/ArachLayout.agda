{-# OPTIONS --safe --without-K #-}

module ArachLayout where

data Empty : Set where

Not : Set -> Set
Not proposition = proposition -> Empty

data Nat : Set where
  zero : Nat
  suc : Nat -> Nat

data Region : Nat -> Set where
  kernel : {n : Nat} -> Region (suc n)
  rustd : {n : Nat} -> Region (suc n)
  bootstrap : {n : Nat} -> Region (suc n)

data BootLayout : Nat -> Set where
  sealed : {n : Nat} -> Region (suc n) -> Region (suc n) -> Region (suc n) -> BootLayout (suc n)

noLayoutWithoutCapacity : Not (BootLayout zero)
noLayoutWithoutCapacity ()

threeArtifactsRequireCapacity : Not (BootLayout zero)
threeArtifactsRequireCapacity ()
