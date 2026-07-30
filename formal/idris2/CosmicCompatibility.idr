||| Total release-gate model for the complete COSMIC desktop.
module CosmicCompatibility

%default total

public export
record Evidence where
  constructor MkEvidence
  processAbi : Bool
  dynamicElf : Bool
  deviceFs : Bool
  input : Bool
  graphics : Bool
  audio : Bool
  serviceManager : Bool
  greeter : Bool
  session : Bool
  compositor : Bool
  desktopComponents : Bool
  portals : Bool
  endurance : Bool

public export
data Gate
  = ProcessAbi
  | DynamicElf
  | DeviceFs
  | Input
  | Graphics
  | Audio
  | ServiceManager
  | Greeter
  | Session
  | Compositor
  | DesktopComponents
  | Portals
  | Endurance

public export
gateReady : Gate -> Evidence -> Bool
gateReady ProcessAbi e = e.processAbi
gateReady DynamicElf e = e.dynamicElf
gateReady DeviceFs e = e.deviceFs
gateReady Input e = e.input
gateReady Graphics e = e.graphics
gateReady Audio e = e.audio
gateReady ServiceManager e = e.serviceManager
gateReady Greeter e = e.greeter
gateReady Session e = e.session
gateReady Compositor e = e.compositor
gateReady DesktopComponents e = e.desktopComponents
gateReady Portals e = e.portals
gateReady Endurance e = e.endurance

public export
required : List Gate
required =
  [ ProcessAbi, DynamicElf, DeviceFs, Input, Graphics, Audio
  , ServiceManager, Greeter, Session, Compositor, DesktopComponents
  , Portals, Endurance
  ]

public export
firstMissing : Evidence -> List Gate -> Maybe Gate
firstMissing evidence [] = Nothing
firstMissing evidence (gate :: rest) =
  if gateReady gate evidence
     then firstMissing evidence rest
     else Just gate

public export
data Decision = Release | Reject Gate

public export
decide : Evidence -> Decision
decide evidence =
  case firstMissing evidence required of
    Nothing => Release
    Just gate => Reject gate

