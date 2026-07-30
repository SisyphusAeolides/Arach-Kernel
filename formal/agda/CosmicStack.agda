{-# OPTIONS --safe --without-K #-}
module CosmicStack where

data Bool : Set where
  false true : Bool

infixr 6 _and_

_and_ : Bool -> Bool -> Bool
true and value = value
false and value = false

record Evidence : Set where
  constructor evidence
  field
    processAbi dynamicElf deviceFs input graphics audio : Bool
    serviceManager greeter session compositor : Bool
    desktopComponents portals endurance : Bool

complete : Evidence -> Bool
complete e =
  Evidence.processAbi e and
  Evidence.dynamicElf e and
  Evidence.deviceFs e and
  Evidence.input e and
  Evidence.graphics e and
  Evidence.audio e and
  Evidence.serviceManager e and
  Evidence.greeter e and
  Evidence.session e and
  Evidence.compositor e and
  Evidence.desktopComponents e and
  Evidence.portals e and
  Evidence.endurance e

data _equals_ {A : Set} (value : A) : A -> Set where
  reflexive : value equals value

data Certified (e : Evidence) : Set where
  certify : complete e equals true -> Certified e

