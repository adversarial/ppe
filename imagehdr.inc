struct IMAGE_DOS_HEADER
        e_magic         dw ?        ; Magic number
        e_cblp          dw ?         ; Bytes on last page of file
        e_cp            dw ?           ; Pages in file
        e_crlc          dw ?         ; Relocations
        e_cparhdr       dw ?      ; Size of header in paragraphs
        e_minalloc      dw ?     ; Minimum extra paragraphs needed
        e_maxalloc      dw ?     ; Maximum extra paragraphs needed
        e_ss            dw ?           ; Initial (relative) SS value
        e_sp            dw ?           ; Initial SP value
        e_csum          dw ?         ; Checksum
        e_ip            dw ?           ; Initial IP value
        e_cs            dw ?           ; Initial (relative) CS value
        e_lfarlc        dw ?       ; File address of relocation table
        e_ovno          dw ?         ; Overlay number
        e_res0          dw ?         ; Reserved words
        e_res1          dw ?
        e_res2          dw ?
        e_res3          dw ?
        e_oemid         dw ?        ; OEM identifier (for e_oeminfo)
        e_oeminfo       dw ?      ; OEM information; e_oemid specific
        e_res20         dw ?        ; Reserved words
        e_res21         dw ?
        e_res22         dw ?
        e_res23         dw ?
        e_res24         dw ?
        e_res25         dw ?
        e_res26         dw ?
        e_res27         dw ?
        e_res28         dw ?
        e_res29         dw ?
        e_lfanew        dd ?       ; File address of new exe header
ends

struct IMAGE_FILE_HEADER
        Machine                 dw ?
        NumberOfSections        dw ?
        TimeDateStamp           dd ?
        PointerToSymbolTable    dd ?
        NumberOfSymbols         dd ?
        SizeOfOptionalHeader    dw ?
        characteristics         dw ?
ends
struct IMAGE_DATA_DIRECTORY
        VirtualAddress          dd ?
        Size                    dd ?
ends


struct IMAGE_OPTIONAL_HEADER
        ; Standard fields.
        Magic                       dw ?
        MajorLinkerVersion          db ?
        MinorLinkerVersion          db ?
        SizeOfCode                  dd ?
        SizeOfInitializedData       dd ?
        SizeOfUnitializedData       dd ?
        AddressOfEntryPoint         dd ?
        BaseOfCode                  dd ?
        BaseOfData                  dd ?
        ; NT additional fields.
        ImageBase                   dd ?
        SectionAlignment            dd ?
        FileAlignment               dd ?
        MajorOperatingSystemVersion dw ?
        MinorOperatingSystemVersion dw ?
        MajorImageVersion           dw ?
        MinorImageVersion           dw ?
        MajorSubsystemVersion       dw ?
        MinorSubsystemVersion       dw ?
        W32VersionValue             dd ?
        SizeOfImage                 dd ?
        SizeOfHeaders               dd ?
        CheckSum                    dd ?
        SubSystem                   dw ?
        DllCharacteristics          dw ?
        SizeOfStackReserve          dd ?
        SizeOfStackCommit           dd ?
        SizeOfHeapReserve           dd ?
        SizeOfHeapCommit            dd ?
        LoaderFlags                 dd ?
        NumberOfRvaAndSizes         dd ?
        DataDirectory               db sizeof.IMAGE_DATA_DIRECTORY*15 dup(?)
ends
struct IMAGE_NT_HEADERS
        Signature               dd ?
        FileHeader              IMAGE_FILE_HEADER ?
        OptionalHeader          IMAGE_OPTIONAL_HEADER ?
ends

struct IMAGE_SECTION_HEADER
       Name                     db 8 dup(?)
       union
              PhysicalAddress   dd ?
              VirtualSize       dd ?
       ends
       VirtualAddress           dd ?
       SizeOfRawData            dd ?
       PointerToRawData         dd ?
       PointerToRelocations     dd ?
       PointerToLineNumbers     dd ?
       NumberOfRelocations      dw ?
       NumberOfLinenumbers      dw ?
       Characteristics          dd ?
ends

struct IMAGE_BASE_RELOCATION
       VirtualAddress           dd ?
       SizeOfBlock              dd ?
ends

struct IMAGE_IMPORT_DESCRIPTOR
       union
              Characteristics    dd ?        ; 0 for end of list
              OriginalFirstThunk dd ?        ; rva to original unbound iat
       ends
       TimeDateStamp            dd ?
       ForwaredChain            dd ?
       Name                     dd ?
       FirstThunk               dd ?
ends

struct IMAGE_THUNK_DATA
       union
              ForwarderString   dd ?
              Function          dd ?
              Ordinal           dd ?
              AddressOfData     dd ?
       ends
ends

struct IMAGE_IMPORT_BY_NAME
       Hint     dw ?    ; likely ordinal
       Name     db ?    ; sz array (variable size)
ends

struct IMAGE_EXPORT_DIRECTORY
        Characteristics         dd   ?       ; unused, always 0
        TimeDateStamp           dd   ?       ; unused, always 0
        MajorVersion            dw   ?       ; unused, always 0
        MinorVersion            dw   ?       ; unused, always 0
        nName                   dd   ?       ; RVA to file name
        nBase                   dd   ?       ; Starting ordinal of export functions
        NumberOfFunctions       dd   ?       ; the number of export functions
        NumberOfNames           dd   ?       ; the number of export functions which are export by name
        AddressOfFunctions      dd   ?       ; RVA to EAT
        AddressOfNames          dd   ?       ; RVA to function name table
        AddressOfNameOrdinals   dd   ?       ; RVA to function name ordinal table
ends

IMAGE_DIRECTORY_ENTRY_EXPORT    equ 0
IMAGE_DIRECTORY_ENTRY_IMPORT    equ 1
IMAGE_DIRECTORY_ENTRY_RESOURCE  equ 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION equ 3
IMAGE_DIRECTORY_ENTRY_SECURITY  equ 4
IMAGE_DIRECTORY_ENTRY_BASERELOC equ 5
IMAGE_DIRECTORY_ENTRY_DEBUG     equ 6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE equ 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR equ 8
IMAGE_DIRECTORY_ENTRY_TLS       equ 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG equ 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT equ 11
IMAGE_DIRECTORY_ENTRY_IAT       equ 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT equ 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR equ 14

IMAGE_REL_BASED_HIGHLOW          equ 3

struct MEMORY_BASIC_INFORMATION
       BaseAddress      dd ?
       AllocationBase   dd ?
       AllocationProtect   dd ?
       RegionSize          dd ?
       State               dd ?
       Protect             dd ?
       Type                dd ?
ends
