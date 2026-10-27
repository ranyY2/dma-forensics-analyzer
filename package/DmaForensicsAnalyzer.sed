[Version]
Class=IEXPRESS
SEDVersion=3

[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=
DisplayPrompt=
FinishMessage=
TargetName=__PROJECT_ROOT__\DmaForensicsScanner.exe
FriendlyName=%FriendlyName%
AppLaunched=cmd.exe /c Run-DmaForensics.cmd
PostInstallCmd=<None>
SourceFiles=SourceFiles

[Strings]
FriendlyName=DMA Forensics Analyzer
FILE0="Run-DmaForensics.cmd"
FILE1="Invoke-DmaForensics.ps1"
FILE2="DmaForensics.Core.Source.psm1"
FILE3="Invoke-DmaForensics.Gui.ps1"

[SourceFiles]
SourceFiles0=__PROJECT_ROOT__\package

[SourceFiles0]
%FILE0%=
%FILE1%=
%FILE2%=
%FILE3%=
