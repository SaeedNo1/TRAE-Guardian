#include <string.h>
#include "hde32.h"

#define GET8(p)     (*(const uint8_t *)(p))
#define GET16(p)    (*(const uint16_t *)(p))
#define GET32(p)    (*(const uint32_t *)(p))

unsigned int hde32_disasm(const void *code, hde32s *hs)
{
    const uint8_t *p = (const uint8_t *)code;
    unsigned int len = 0;

    if (!hs)
        return 0;

    memset(hs, 0, sizeof(hde32s));

    if (!p)
        return 0;

    hs->flags = 0;
    hs->len = 0;

    while (1) {
        if (len > 15) {
            hs->flags |= F_ERROR | F_ERROR_LENGTH;
            return len;
        }

        switch (*p) {
        case 0xF3:
            hs->p_rep = *p++;
            len++;
            continue;
        case 0xF2:
            hs->p_rep = *p++;
            len++;
            continue;
        case 0xF0:
            hs->p_lock = *p++;
            len++;
            continue;
        case 0x2E:
        case 0x36:
        case 0x3E:
        case 0x26:
        case 0x64:
        case 0x65:
            hs->p_seg = *p++;
            len++;
            continue;
        case 0x66:
            hs->p_66 = *p++;
            len++;
            hs->operand_size = 2;
            continue;
        case 0x67:
            hs->p_67 = *p++;
            len++;
            hs->addr_size = 2;
            continue;
        default:
            break;
        }
        break;
    }

    hs->opcode = *p++;
    len++;

    if (hs->opcode == 0x0F) {
        hs->opcode2 = *p++;
        len++;
    }

    if (hs->addr_size == 0)
        hs->addr_size = 4;
    if (hs->operand_size == 0)
        hs->operand_size = 4;

    if ((hs->opcode >= 0x80 && hs->opcode <= 0x8F) ||
        (hs->opcode >= 0xC0 && hs->opcode <= 0xCF) ||
        (hs->opcode >= 0xD0 && hs->opcode <= 0xDF) ||
        (hs->opcode >= 0xF6 && hs->opcode <= 0xF7) ||
        (hs->opcode == 0xFE) || (hs->opcode == 0xFF) ||
        (hs->opcode == 0x0F)) {
        hs->modrm = *p++;
        len++;
        hs->modrm_mod = (hs->modrm >> 6) & 3;
        hs->modrm_reg = (hs->modrm >> 3) & 7;
        hs->modrm_rm = hs->modrm & 7;
        hs->flags |= F_MODRM;

        if (hs->modrm_mod != 3 && hs->addr_size == 4 && hs->modrm_rm == 4) {
            hs->sib = *p++;
            len++;
            hs->sib_scale = (hs->sib >> 6) & 3;
            hs->sib_index = (hs->sib >> 3) & 7;
            hs->sib_base = hs->sib & 7;
            hs->flags |= F_SIB;
        }

        if (hs->modrm_mod == 0 && hs->modrm_rm == 5 && hs->addr_size == 4) {
            hs->disp32 = GET32(p);
            p += 4;
            len += 4;
            hs->flags |= F_DISP32;
        } else if (hs->modrm_mod == 1) {
            hs->disp8 = GET8(p);
            p += 1;
            len += 1;
            hs->flags |= F_DISP8;
        } else if (hs->modrm_mod == 2) {
            if (hs->addr_size == 4) {
                hs->disp32 = GET32(p);
                p += 4;
                len += 4;
                hs->flags |= F_DISP32;
            } else {
                hs->disp16 = GET16(p);
                p += 2;
                len += 2;
                hs->flags |= F_DISP16;
            }
        }
    }

    switch (hs->opcode) {
    case 0x05:
    case 0x0D:
    case 0x15:
    case 0x1D:
    case 0x25:
    case 0x2D:
    case 0x35:
    case 0x3D:
        if (hs->operand_size == 4) {
            hs->imm32 = GET32(p);
            p += 4;
            len += 4;
            hs->flags |= F_IMM32;
        } else {
            hs->imm16 = GET16(p);
            p += 2;
            len += 2;
            hs->flags |= F_IMM16;
        }
        break;
    case 0x6A:
        hs->imm8 = GET8(p);
        p += 1;
        len += 1;
        hs->flags |= F_IMM8;
        break;
    case 0x6B:
    case 0x83:
        hs->imm8 = GET8(p);
        p += 1;
        len += 1;
        hs->flags |= F_IMM8;
        break;
    case 0x68:
        if (hs->operand_size == 4) {
            hs->imm32 = GET32(p);
            p += 4;
            len += 4;
            hs->flags |= F_IMM32;
        } else {
            hs->imm16 = GET16(p);
            p += 2;
            len += 2;
            hs->flags |= F_IMM16;
        }
        break;
    default:
        break;
    }

    hs->len = len;
    return hs->len;
}