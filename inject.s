.syntax unified
.thumb
ldr.w r1, [r4, #0xd0] // s->session
ldr r0, [r4, #0x54] // s->s3
blx #0x37af4
