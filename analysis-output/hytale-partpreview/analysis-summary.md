# Hytale PartPreview reverse-engineering reports

## Input
Hytale reverse-engineering input hashes
7c23fcfac81cfcec60a9312a40db8f2563a4eda4668a5ebc2bbc86fc9cadd268  HytaleClient.7z
0406a4c3cfef099ef2dff318cb889726d9c9883a0c12007fdda0563e93a0f80e  /home/runner/work/_temp/hytale-input/HytaleClient.exe
EXE_SIZE=72830816
/home/runner/work/_temp/hytale-input/HytaleClient.exe: PE32+ executable (GUI) x86-64, for MS Windows, 6 sections

## Rizin target strings

## Ghidra target overview
PROGRAM=HytaleClient.exe
IMAGE_BASE=140000000
LANGUAGE=x86:LE:64:default
STRING 143e68e44 :: FallbackPartId
  XREF 140838b85 type=DATA function=FUN_140837df0 entry=140837df0
STRING 143e68e7c :: FallbackPartIds
  XREF 1408386e4 type=DATA function=FUN_140837df0 entry=140837df0
STRING 143ebd28c :: PartId = 
  XREF 140b5710a type=PARAM function=FUN_140b570f0 entry=140b570f0
STRING_HITS=3
UNIQUE_XREF_FUNCTIONS=2
FUNCTION FUN_140837df0 entry=140837df0
CALLEE FUN_14203cc00 entry=14203cc00
CALLEE FUN_1411c69f0 entry=1411c69f0
CALLEE FUN_141f908b8 entry=141f908b8
CALLEE FUN_14203c5d0 entry=14203c5d0
CALLEE FUN_1411ec610 entry=1411ec610
CALLEE FUN_141019c80 entry=141019c80
CALLEE thunk_FUN_14104c200 entry=141fca4c4
CALLEE FUN_1411ec6a0 entry=1411ec6a0
CALLEE FUN_1411bae60 entry=1411bae60
CALLEE FUN_1411c6970 entry=1411c6970
CALLEE FUN_14203cdf0 entry=14203cdf0
FUNCTION FUN_140b570f0 entry=140b570f0
CALLER FUN_140b56fa0 entry=140b56fa0
CALLEE FUN_140fe7bd0 entry=140fe7bd0
CALLEE FUN_14101cab0 entry=14101cab0
CALLEE FUN_140fe7c40 entry=140fe7c40
