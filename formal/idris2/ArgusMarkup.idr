module ArgusMarkup

%default total

public export
data NodeKind = Heading | Paragraph | Link

public export
record ParserState where
  constructor MkParserState
  activeTag : Bool
  nodes : Nat
  textBytes : Nat

public export
MAX_NODES : Nat
MAX_NODES = 32

public export
MAX_TEXT_BYTES : Nat
MAX_TEXT_BYTES = 1024

public export
admit : ParserState -> Nat -> ParserState
admit (MkParserState True nodes bytes) length =
  MkParserState True (S nodes) (bytes + length)
admit state _ = state

public export
closedCannotAdmit :
  admit (MkParserState False 0 0) 7 = MkParserState False 0 0
closedCannotAdmit = Refl

public export
openedAdmissionAddsExactlyOneNode :
  admit (MkParserState True 3 12) 9 = MkParserState True 4 21
openedAdmissionAddsExactlyOneNode = Refl

public export
localTarget : List Char -> Bool
localTarget ('s' :: 'i' :: 's' :: 'y' :: 'p' :: 'h' :: 'u' :: 's' :: ':' :: '/' :: '/' :: rest) = True
localTarget _ = False

public export
externalTargetRejected :
  localTarget ('h' :: 't' :: 't' :: 'p' :: 's' :: ':' :: '/' :: '/' :: []) = False
externalTargetRejected = Refl

public export
measuredTargetAdmitted :
  localTarget ('s' :: 'i' :: 's' :: 'y' :: 'p' :: 'h' :: 'u' :: 's' :: ':' :: '/' :: '/' :: 'h' :: 'o' :: 'm' :: 'e' :: []) = True
measuredTargetAdmitted = Refl

public export
data NavigationPolicy = MeasuredOnly | BrokeredHttps

public export
data HypermediaTarget = MeasuredDocument | HttpsDocument | ScriptDocument

public export
targetAdmitted : NavigationPolicy -> HypermediaTarget -> Bool
targetAdmitted MeasuredOnly MeasuredDocument = True
targetAdmitted MeasuredOnly HttpsDocument = False
targetAdmitted MeasuredOnly ScriptDocument = False
targetAdmitted BrokeredHttps MeasuredDocument = True
targetAdmitted BrokeredHttps HttpsDocument = True
targetAdmitted BrokeredHttps ScriptDocument = False

public export
scriptNeverAdmitted :
  targetAdmitted BrokeredHttps ScriptDocument = False
scriptNeverAdmitted = Refl

public export
externalTargetNeedsBroker :
  targetAdmitted MeasuredOnly HttpsDocument = False
externalTargetNeedsBroker = Refl

public export
brokeredHttpsIsDataOnly :
  targetAdmitted BrokeredHttps HttpsDocument = True
brokeredHttpsIsDataOnly = Refl

public export
record WorkBudget where
  constructor MkWorkBudget
  segments : Nat
  yieldEvery : Nat

public export
mustYield : WorkBudget -> Bool
mustYield (MkWorkBudget (S _) (S _)) = True
mustYield _ = False

public export
positiveBoundForcesYield :
  mustYield (MkWorkBudget 16 1) = True
positiveBoundForcesYield = Refl
