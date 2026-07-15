#ifndef HDE32_H
#define HDE32_H

#include <stdint.h>

#define F_MODRM        0x01
#define F_SIB          0x02
#define F_DISP8        0x04
#define F_DISP16       0x08
#define F_DISP32       0x10
#define F_IMM8         0x20
#define F_IMM16        0x40
#define F_IMM32        0x80

#define F_ERROR        0x0100
#define F_ERROR_OPCODE 0x0200
#define F_ERROR_LENGTH 0x0400
#define F_ERROR_LOCK   0x0800
#define F_ERROR_OPERAND 0x1000

typedef struct {
    uint8_t len;
    uint8_t p_rep;
    uint8_t p_lock;
    uint8_t p_seg;
    uint8_t p_66;
    uint8_t p_67;
    uint8_t opcode;
    uint8_t opcode2;
    uint8_t modrm;
    uint8_t modrm_mod;
    uint8_t modrm_reg;
    uint8_t modrm_rm;
    uint8_t sib;
    uint8_t sib_scale;
    uint8_t sib_index;
    uint8_t sib_base;
    int8_t disp8;
    int16_t disp16;
    int32_t disp32;
    uint8_t imm8;
    uint16_t imm16;
    uint32_t imm32;
    uint8_t flags;
    uint8_t opcode_table_id;
    uint8_t addr_size;
    uint8_t operand_size;
} hde32s;

#ifdef __cplusplus
extern "C" {
#endif

unsigned int hde32_disasm(const void *code, hde32s *hs);

#ifdef __cplusplus
}
#endif

#endif