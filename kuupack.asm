; Released under the MIT License (MIT)

; Copyright (c) 2013 kuupa

; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:

; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.

; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
; THE SOFTWARE.

;==============================================================================
; PPE - Packer for Portable Executables
; Copyright (c) 2013 - kuupa -- see LICENSE
;==============================================================================
;
;       The executable is stored in the final section, so that it does not need
; relocations (as we can simply load it over our own headers and pad with
; virtualsize to keep our module running).

;       Nothing is needed at runtime, to build a simple script to read the
; attributes from the payload and write to 'packer_constants.inc' and then run
; fasm.

;       Doesn't currently support TLS callbacks

;======= Std ===========
include '%inc%\win32a.inc'
;======= Local =========
include '.\imagehdr.inc'
;=======================
include '.\packer_constants.inc'

format PE GUI 6.0 NX at BASEADDRESS
entry _entry

;=======================================
; Constants
;=======================================

;======== Unpacked loading space =======
section '.bss' data readable writable
;=======================================
VirtualPayload:

  .payload db VIRTUALSIZE+1 dup(?)

;======== Packer code ==================
section '.text' code readable executable
;=======================================
_entry:
        sub esp, $4

        xor edx, edx
        invoke GetModuleHandleA,edx
        ; assert(eax)

        mov edi, eax
        invoke VirtualProtect,eax,1,PAGE_READWRITE,esp

        mov esi, pDecompressed
        ccall aP_depack_asm,pPayload,esi
        stdcall loadpe
        call eax

        add esp, $4
        invoke ExitProcess,eax

loadpe: ; in esi = file aligned pe
        ; in edi = dest
        ; out eax = void (*entrypoint)(void);
        push ebx esi edi ebp

        push esi        ; [esp+4*2] is file base
        push edi        ; [esp+4*1] is module base

        cld

        movzx ecx, word [esi+IMAGE_DOS_HEADER.e_cparhdr]
        shl ecx, 4

        push esi edi
        rep movsb
        pop edi esi

        mov eax, [esi+IMAGE_DOS_HEADER.e_lfanew]

        add esi, eax
        add edi, eax
        mov ebp, esi    ; save nt headers*

        movzx eax, word [esi+IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
        lea ecx, [eax+esi+sizeof.IMAGE_FILE_HEADER+4]

        mov ebx, ecx    ; save section headers*

        mov edx, sizeof.IMAGE_SECTION_HEADER
        movzx eax, word [esi+IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
        push eax
          mul edx
          xadd eax, ecx ; ecx = sizeof pe headers

          rep movsb

        pop edx         ; number of sections

        mov eax, ebx
  .loadsec:
          mov ecx, [eax+IMAGE_SECTION_HEADER.SizeOfRawData]
          mov esi, [eax+IMAGE_SECTION_HEADER.PointerToRawData]
          add esi, [esp+4*1]; file base
          mov edi, [eax+IMAGE_SECTION_HEADER.VirtualAddress]
          add edi, [esp+4*0]; module base

          rep movsb         ; not guaranteed to not be aligned to 1

          add eax, sizeof.IMAGE_SECTION_HEADER
          sub edx, 1
          jnz .loadsec

        ; ebp = nt_headers*
        ; ebx = section_header*
        ; [esp+0] = module base
        ; [esp+4] = file base

        push ebx
  .imports:
        lea edi, [ebp+IMAGE_NT_HEADERS.OptionalHeader.DataDirectory+sizeof.IMAGE_DATA_DIRECTORY*IMAGE_DIRECTORY_ENTRY_IMPORT]
        mov eax, [edi+IMAGE_DATA_DIRECTORY.Size]
        test eax, eax
        jz .noimports

        mov edi, [edi+IMAGE_DATA_DIRECTORY.VirtualAddress]
        test edi, edi
        jz .noimports

        add edi, [esp+4+4*0]      ; to va

    .importlibraryloop:
        mov eax, [edi+IMAGE_IMPORT_DESCRIPTOR.Characteristics]
        test eax, eax
        jz .doneimports         ; null terminated list

        mov eax, [edi+IMAGE_IMPORT_DESCRIPTOR.Name]
        add eax, [esp+4+4*0]

        invoke LoadLibraryA,eax
        mov ebx, eax

        mov esi, [edi+IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
        add esi, [esp+4+4*0]

        ; edi = thunk_data*
      .importitemloop:
        lodsd                   ; thunk_data is dword union
        test eax, eax
        jz .importlibrarynext
        js .importbyordinal     ; hi bit = IMAGE_ORDINAL_FLAG

      .importbyname:
        add eax, IMAGE_IMPORT_BY_NAME.Name ; skip hint
        add eax, [esp+4+4*0]
        jmp .importfunction
      .importbyordinal:
        and eax, $ffff          ; hi word must be 0 for getprocaddr

      .importfunction:
        invoke GetProcAddress,ebx,eax
        mov [esi-4], eax        ; save item ptr

    .importlibrarynext:
        add edi, sizeof.IMAGE_IMPORT_DESCRIPTOR
        jmp .importlibraryloop

    .doneimports:
    .noimports:
        pop ebx

        ; ebp = nt_headers*
        ; ebx = section_header*
        ; [esp+4] = module base
        ; [esp+8] = file base
  .protect:

        ; protect headers (r)
        sub esp, $4
        mov eax, [esp+4]
        invoke VirtualProtect,eax,1,PAGE_READONLY,esp
        add esp, $4

        movzx edi, word [ebp+IMAGE_NT_HEADERS.FileHeader.NumberOfSections]

        mov esi, 4
    .protectsection:
        mov eax, [ebx+IMAGE_SECTION_HEADER.Characteristics]
        shr eax, 3*8+5  ; rest of flags are irrelevant (top 3 bits)

  ; al = 0000`0wre

        xor ecx, ecx
        mov edx, eax
        and edx, $6     ; 0000`0wr0

        cmp eax, 6      ; if r && w
        cmove edx, esi ; set r/w

        xor ecx, ecx
        test eax, $1    ; if e
        cmovnz ecx, esi ; shift to second nibble
        shl edx, cl

  ; we only care about protection attributes to execute

        mov eax, [ebx+IMAGE_SECTION_HEADER.VirtualAddress]
        add eax, [esp+4*0]

        mov ecx, [ebx+IMAGE_SECTION_HEADER.VirtualSize]

        sub esp, 4      ; for old protection (page_readwrite)
        invoke VirtualProtect,eax,ecx,edx,esp
        add esp, 4

    .protectnext:
        add ebx, sizeof.IMAGE_SECTION_HEADER
        sub edi, 1
        jnz .protectsection

        ; tls

  .callep:
        mov eax, [ebp+IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint]
        add eax, [esp+4*0]

        add esp, 4*2    ; saved module and file base
        pop ebx esi edi ebp
        ret

;;
;; aPLib compression library  -  the smaller the better :)
;;
;; fasm assembler depacker
;;
;; Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

aP_depack_asm:
    ; aP_depack_asm(const void *source, void *destination)

    _ret$  equ 7*4
    _src$  equ 8*4 + 4
    _dst$  equ 8*4 + 8

    pushad

    mov    esi, [esp + _src$] ; C calling convention
    mov    edi, [esp + _dst$]

    cld
    mov    dl, 80h
    xor    ebx,ebx

literal:
    movsb
    mov    bl, 2
nexttag:
    call   getbit
    jnc    literal

    xor    ecx, ecx
    call   getbit
    jnc    codepair
    xor    eax, eax
    call   getbit
    jnc    shortmatch
    mov    bl, 2
    inc    ecx
    mov    al, 10h
  .getmorebits:
    call   getbit
    adc    al, al
    jnc    .getmorebits
    jnz    domatch
    stosb
    jmp    nexttag
codepair:
    call   getgamma_no_ecx
    sub    ecx, ebx
    jnz    normalcodepair
    call   getgamma
    jmp    domatch_lastpos

shortmatch:
    lodsb
    shr    eax, 1
    jz     donedepacking
    adc    ecx, ecx
    jmp    domatch_with_2inc

normalcodepair:
    xchg   eax, ecx
    dec    eax
    shl    eax, 8
    lodsb
    call   getgamma

    cmp    eax, 32000
    jae    domatch_with_2inc
    cmp    ah, 5
    jae    domatch_with_inc
    cmp    eax, 7fh
    ja     domatch_new_lastpos

domatch_with_2inc:
    inc    ecx

domatch_with_inc:
    inc    ecx

domatch_new_lastpos:
    xchg   eax, ebp
domatch_lastpos:
    mov    eax, ebp

    mov    bl, 1

domatch:
    push   esi
    mov    esi, edi
    sub    esi, eax
    rep    movsb
    pop    esi
    jmp    nexttag

getbit:
    add    dl, dl
    jnz    .stillbitsleft
    mov    dl, [esi]
    inc    esi
    adc    dl, dl
  .stillbitsleft:
    ret

getgamma:
    xor    ecx, ecx
getgamma_no_ecx:
    inc    ecx
  .getgammaloop:
    call   getbit
    adc    ecx, ecx
    call   getbit
    jc     .getgammaloop
    ret

donedepacking:
    sub    edi, [esp + _dst$]
    mov    [esp + _ret$], edi ; return unpacked length in eax

    popad

    ret

;=======================================
; reloc data directory (.reloc)
; removed by builder
;=======================================
;data fixups
; auto filled
;end data


;=======================================
; import data directory (.idata)
;=======================================
data import
library kernel32,'kernel32.dll',\
        user32,'user32.dll'

import kernel32,\
       ExitProcess,'ExitProcess',\
       GetModuleHandleA,'GetModuleHandleA',\
       GetProcAddress,'GetProcAddress',\
       LoadLibraryA,'LoadLibraryA',\
       VirtualProtect,'VirtualProtect'

; random shit
import user32,\
       CreateWindowA,'CreateWindowA',\
       DispatchMessage,'DispatchMessage',\
       RegisterClassExA,'RegisterClassExA',\
       ShowWindow,'ShowWindow',\
       TranslateMessage,'TranslateMessage'

end data

;======== PE File ======================
section '.data' data readable writeable
;=======================================
CompressedHeader:
  .RawSize dd RAWSIZE
  .VirtualSize dd VIRTUALSIZE
pPayload:
  file TARGET_FILE
pDecompressed db RAWSIZE + 1 dup(?)




