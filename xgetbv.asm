.code

PUBLIC xgetbv_asm  

xgetbv_asm PROC
    ; XGETBV instruction requires ECX to be pre-loaded with the XCR index (usually 0)
    xor eax, eax
    xor edx, edx
    xgetbv
    ret
xgetbv_asm ENDP

END