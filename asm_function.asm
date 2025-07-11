.code

PUBLIC xgetbv_asm

; uint64_t xgetbv_asm(uint32_t ecx)

xgetbv_asm PROC
    ; ecx is in ecx already

    xgetbv              ; output edx:eax

    shl rdx, 32         ; shift edx to high 32 bits
    or rax, rdx         ; combine edx:eax to rax

    ret

xgetbv_asm ENDP



END


