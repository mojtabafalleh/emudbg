.code

PUBLIC xgetbv_asm  

xgetbv_asm PROC
    xor eax, eax
    xor edx, edx
    xgetbv
    ret
xgetbv_asm ENDP

END