.syntax unified
.arm
.text
.global ReadRawPen
.type ReadRawPen, %function
ReadRawPen:
    push {r4, lr}
    sub sp, sp, #16
    mov r4, r1
    mov r0, sp
    bl ReadHalPosition
    cmp r0, #0
    bne 1f
    ldrh r1, [sp]
    ldrh r2, [sp, #2]
    mov r3, r1, lsr #8
    strb r3, [r4]
    strb r1, [r4, #1]
    mov r3, r2, lsr #8
    strb r3, [r4, #2]
    strb r2, [r4, #3]
1:
    add sp, sp, #16
    pop {r4, lr}
    bx lr

ReadHalPosition:
    @ Garnet native HALPenGetPosition, using the ROM HAL table.
    ldr ip, [r9, #-4]
    ldr pc, [ip, #0x164]
