#include <string.h>
#include "hde64.h"

#define GET8(p)     (*(const uint8_t *)(p))
#define GET16(p)    (*(const uint16_t *)(p))
#define GET32(p)    (*(const uint32_t *)(p))

unsigned int hde64_disasm(const void *code, hde64s *hs)
{
    const uint8_t *p = (const uint8_t *)code;
    unsigned int len = 0;

    if (!hs)
        return 0;

    memset(hs, 0, sizeof(hde64s));

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
            continue;
        case 0x67:
            hs->p_67 = *p++;
            len++;
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
        if (hs->opcode2 == 0x38 || hs->opcode2 == 0x3A) {
            hs->modrm = *p++;
            len++;
            hs->modrm_mod = (hs->modrm >> 6) & 3;
            hs->modrm_reg = (hs->modrm >> 3) & 7;
            hs->modrm_rm = hs->modrm & 7;
            hs->flags |= F_MODRM;
        }
    }

    if ((hs->opcode >= 0x80 && hs->opcode <= 0x8F) ||
        (hs->opcode >= 0xC0 && hs->opcode <= 0xCF) ||
        (hs->opcode >= 0xD0 && hs->opcode <= 0xDF) ||
        (hs->opcode >= 0xF6 && hs->opcode <= 0xF7) ||
        (hs->opcode == 0xFE) || (hs->opcode == 0xFF) ||
        (hs->opcode == 0x0F)) {
        if (!(hs->opcode == 0x0F && (hs->opcode2 == 0x38 || hs->opcode2 == 0x3A))) {
            hs->modrm = *p++;
            len++;
            hs->modrm_mod = (hs->modrm >> 6) & 3;
            hs->modrm_reg = (hs->modrm >> 3) & 7;
            hs->modrm_rm = hs->modrm & 7;
            hs->flags |= F_MODRM;
        }

        if (hs->modrm_mod != 3 && hs->modrm_rm == 4) {
            hs->sib = *p++;
            len++;
            hs->sib_scale = (hs->sib >> 6) & 3;
            hs->sib_index = (hs->sib >> 3) & 7;
            hs->sib_base = hs->sib & 7;
            hs->flags |= F_SIB;
        }

        if (hs->modrm_mod == 0 && hs->modrm_rm == 5) {
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
            hs->disp32 = GET32(p);
            p += 4;
            len += 4;
            hs->flags |= F_DISP32;
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
        hs->imm32 = GET32(p);
        p += 4;
        len += 4;
        hs->flags |= F_IMM32;
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
        hs->imm32 = GET32(p);
        p += 4;
        len += 4;
        hs->flags |= F_IMM32;
        break;
    case 0xB8:
    case 0xB9:
    case 0xBA:
    case 0xBB:
    case 0xBC:
    case 0xBD:
    case 0xBE:
    case 0xBF:
        if (hs->p_66 == 0) {
            hs->imm64 = *(const uint64_t *)p;
            p += 8;
            len += 8;
            hs->flags |= F_IMM64;
        } else {
            hs->imm32 = GET32(p);
            p += 4;
            len += 4;
            hs->flags |= F_IMM32;
        }
        break;
    default:
        break;
    }

    if (hs->opcode == 0x0F) {
        switch (hs->opcode2) {
        case 0x05:
        case 0x0D:
        case 0x15:
        case 0x1D:
        case 0x25:
        case 0x2D:
        case 0x35:
        case 0x3D:
            hs->imm32 = GET32(p);
            p += 4;
            len += 4;
            hs->flags |= F_IMM32;
            break;
        case 0x6C:
        case 0x6D:
        case 0xA9:
        case 0xAB:
            hs->imm32 = GET32(p);
            p += 4;
            len += 4;
            hs->flags |= F_IMM32;
            break;
        default:
            break;
        }
    }

    hs->len = len;
    return hs->len;
}