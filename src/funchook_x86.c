/* -*- indent-tabs-mode: nil -*-
 *
 * This file is part of Funchook.
 * https://github.com/kubo/funchook
 *
 * Funchook is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the License, or (at your
 * option) any later version.
 *
 * As a special exception, the copyright holders of this library give you
 * permission to link this library with independent modules to produce an
 * executable, regardless of the license terms of these independent
 * modules, and to copy and distribute the resulting executable under
 * terms of your choice, provided that you also meet, for each linked
 * independent module, the terms and conditions of the license of that
 * module. An independent module is a module which is not derived from or
 * based on this library. If you modify this library, you may extend this
 * exception to your version of the library, but you are not obliged to
 * do so. If you do not wish to do so, delete this exception statement
 * from your version.
 *
 * Funchook is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Funchook. If not, see <http://www.gnu.org/licenses/>.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "funchook_internal.h"
#include "disasm.h"

typedef struct {
    funchook_t *funchook;
    ip_displacement_t *rip_disp;
    const uint8_t *src;
    const uint8_t *dst_base;
    uint8_t *dst;
} make_trampoline_context_t;

#define NOP_INSTRUCTION 0x90

#if defined(__i386)
static int handle_x86_get_pc_thunk(make_trampoline_context_t *ctx, const funchook_insn_t *di);
static int handle_x86_get_pc_by_call_and_pop(make_trampoline_context_t *ctx, const funchook_insn_t *di);
#else
#define handle_x86_get_pc_thunk(ctx, di) (0)
#define handle_x86_get_pc_by_call_and_pop(ctx, di) (0)
#endif

static int handle_rip_relative(make_trampoline_context_t *ctx, const rip_relative_t *rel, size_t insn_size);

static int funchook_write_jump32(funchook_t *funchook, const uint8_t *src, const uint8_t *dst, uint8_t *out)
{
    out[0] = 0xe9;
    *(int*)(out + 1) = (int)(dst - (src + 5));
    funchook_log(funchook, "  Write jump32 0x"ADDR_FMT" -> 0x"ADDR_FMT"\n",
                 (size_t)src, (size_t)dst);
    return 0;
}

#ifdef CPU_X86_64

static int funchook_write_jump64(funchook_t *funchook, uint8_t *src, const uint8_t *dst)
{
    src[0] = 0xFF;
    src[1] = 0x25;
    src[2] = 0x00;
    src[3] = 0x00;
    src[4] = 0x00;
    src[5] = 0x00;
    *(const uint8_t**)(src + 6) = dst;
    funchook_log(funchook, "  Write jump64 0x"ADDR_FMT" -> 0x"ADDR_FMT"\n",
                 (size_t)src, (size_t)dst);
    return 0;
}

static int funchook_within_32bit_relative(const uint8_t *src, const uint8_t *dst)
{
    int64_t diff = (int64_t)(dst - src);
    return (INT32_MIN <= diff && diff <= INT32_MAX);
}

static int funchook_jump32_avail(const uint8_t *src, const uint8_t *dst)
{
    return funchook_within_32bit_relative(src + 5, dst);
}

#endif

int funchook_make_trampoline(funchook_t *funchook, ip_displacement_t *disp, const uint8_t *func, uint8_t *trampoline, size_t *trampoline_size)
{
    make_trampoline_context_t ctx;
    funchook_disasm_t disasm;
    int rv;
    const funchook_insn_t *insn;

    memset(disp, 0, sizeof(*disp));
    memset(trampoline, NOP_INSTRUCTION, TRAMPOLINE_SIZE);
    *trampoline_size = 0;
    ctx.funchook = funchook;
    ctx.rip_disp = disp;
    ctx.src = func;
    ctx.dst_base = ctx.dst = trampoline;

    rv = funchook_disasm_init(&disasm, funchook, func, MAX_INSN_CHECK_SIZE, (size_t)func);
    if (rv != 0) {
        return rv;
    }

    funchook_log(funchook, "  Original Instructions:\n");
    while ((rv = funchook_disasm_next(&disasm, &insn)) == 0) {
        rip_relative_t rel_disp;
        rip_relative_t rel_imm;

        funchook_disasm_log_instruction(&disasm, insn);

        if (handle_x86_get_pc_thunk(&ctx, insn)) {
            ;
        } else if (handle_x86_get_pc_by_call_and_pop(&ctx, insn)) {
            if ((rv = funchook_disasm_next(&disasm, &insn)) == 0) {
                funchook_disasm_log_instruction(&disasm, insn);
            }
        } else {
            size_t insn_size = funchook_insn_size(insn);
            memcpy(ctx.dst, ctx.src, insn_size);
            funchook_disasm_x86_rip_relative(&disasm, insn, &rel_disp, &rel_imm);
            rv = handle_rip_relative(&ctx, &rel_disp, insn_size);
            if (rv != 0) {
                goto cleanup;
            }
            rv = handle_rip_relative(&ctx, &rel_imm, insn_size);
            if (rv != 0) {
                goto cleanup;
            }
            ctx.src += insn_size;
            ctx.dst += insn_size;
        }
        if (ctx.src - func >= JUMP32_SIZE) {
            ctx.dst[0] = 0xe9; /* unconditional jump */
            disp->disp[0].dst_addr = ctx.src;
            disp->disp[0].src_addr_offset = (ctx.dst - ctx.dst_base) + 5;
            disp->disp[0].pos_offset = (ctx.dst - ctx.dst_base) + 1;
            *trampoline_size = (ctx.dst - ctx.dst_base) + 5;
            while ((rv = funchook_disasm_next(&disasm, &insn)) == 0) {
                funchook_disasm_log_instruction(&disasm, insn);
                funchook_disasm_x86_rip_relative(&disasm, insn, &rel_disp, &rel_imm);
                if (func < rel_imm.addr && rel_imm.addr < func + JUMP32_SIZE) {
                    /* jump to the hot-patched region. */
                    funchook_set_error_message(funchook, "instruction jumping back to the hot-patched region was found");
                    rv = FUNCHOOK_ERROR_FOUND_BACK_JUMP;
                    goto cleanup;
                }
            }
            break;
        }
    }
    if (rv != FUNCHOOK_ERROR_END_OF_INSTRUCTION) {
        goto cleanup;
    }
    rv = 0;
    /* too short function. Check whether NOP instructions continue. */
    while (ctx.src - func < JUMP32_SIZE) {
        if (*ctx.src != NOP_INSTRUCTION) {
            funchook_set_error_message(funchook, "Too short instructions");
            rv = FUNCHOOK_ERROR_TOO_SHORT_INSTRUCTIONS;
            goto cleanup;
        }
        ctx.src++;
    }
cleanup:
    funchook_disasm_cleanup(&disasm);
    return rv;
}

#ifndef handle_x86_get_pc_thunk
/* special cases to handle "call __x86.get_pc_thunk.??"
 * If the target instructions are "movl (%esp), %???; ret",
 * use "movl addr + 5, %???" instead.
 */
static int handle_x86_get_pc_thunk(make_trampoline_context_t *ctx, const funchook_insn_t *insn)
{
    uint32_t eip = 0;
    const char *reg_name = NULL;

    if (*ctx->src == 0xe8) {
        uint32_t first_4_bytes = *(uint32_t*)funchook_insn_branch_address(insn);

        eip = funchook_insn_address(insn) + 5;
        switch (first_4_bytes) {
        case 0xc324048b: /* 8b 04 24 c3: movl (%esp), %eax; ret */
            reg_name = "ax";
            *ctx->dst = 0xb8; /*         movl addr + 5, %eax */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc3241c8b: /* 8b 1c 24 c3: movl (%esp), %ebx; ret */
            reg_name = "bx";
            *ctx->dst = 0xbb; /*         movl addr + 5, %ebx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc3240c8b: /* 8b 0c 24 c3: movl (%esp), %ecx; ret */
            reg_name = "cx";
            *ctx->dst = 0xb9; /*         movl addr + 5, %ecx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc324148b: /* 8b 14 24 c3: movl (%esp), %edx; ret */
            reg_name = "dx";
            *ctx->dst = 0xba; /*         movl addr + 5, %edx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc324348b: /* 8b 34 24 c3: movl (%esp), %esi; ret */
            reg_name = "si";
            *ctx->dst = 0xbe; /*         movl addr + 5, %esi */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc3243c8b: /* 8b 3c 24 c3: movl (%esp), %edi; ret */
            reg_name = "di";
            *ctx->dst = 0xbf; /*         movl addr + 5, %edi */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0xc3242c8b: /* 8b 2c 24 c3: movl (%esp), %ebp; ret */
            reg_name = "bp";
            *ctx->dst = 0xbd; /*         movl addr + 5, %ebp */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        }
    }
    return 0;

fixed:
    funchook_log(ctx->funchook, "      use 'MOV E%c%c, 0x%x' instead of 'CALL __x86.get_pc_thunk.%s'\n",
                 reg_name[0] + 'A' - 'a',
                 reg_name[1] + 'A' - 'a',
                 eip, reg_name);
    ctx->dst += 5;
    ctx->src += 5;
    return 1;
}
#endif

#ifndef handle_x86_get_pc_by_call_and_pop
static int handle_x86_get_pc_by_call_and_pop(make_trampoline_context_t *ctx, const funchook_insn_t *insn)
{
    uint32_t eip = 0;
    const char *reg_name = NULL;

    if (*ctx->src == 0xe8 && *(uint32_t*)(ctx->src + 1) == 0) {
        eip = funchook_insn_address(insn) + 5;
        switch (*(ctx->src + 5)) {
        case 0x58: /* pop %eax */
            reg_name = "EAX";
            *ctx->dst = 0xb8; /* movl addr + 5, %eax */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x5b: /* pop %ebx */
            reg_name = "EBX";
            *ctx->dst = 0xbb; /* movl addr + 5, %ebx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x59: /* pop %ecx */
            reg_name = "ECX";
            *ctx->dst = 0xb9; /* movl addr + 5, %ecx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x5a: /* pop %edx */
            reg_name = "EDX";
            *ctx->dst = 0xba; /* movl addr + 5, %edx */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x5e: /* pop %esi */
            reg_name = "ESI";
            *ctx->dst = 0xbe; /* movl addr + 5, %esi */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x5f: /* pop %edi */
            reg_name = "EDI";
            *ctx->dst = 0xbf; /* movl addr + 5, %edi */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        case 0x5d: /* pop %ebp */
            reg_name = "EBP";
            *ctx->dst = 0xbd; /* movl addr + 5, %ebp */
            *(uint32_t*)(ctx->dst + 1) = eip;
            goto fixed;
        }
    }
    return 0;

fixed:
    funchook_log(ctx->funchook, "      use 'MOV %s, 0x%x' instead of 'CALL 0x%x; POP %s'\n",
                 reg_name, eip, eip, reg_name);
    ctx->dst += 5;
    ctx->src += 6;
    return 1;

}
#endif

/*
 * Fix RIP-relative address in an instruction
 */
static int handle_rip_relative(make_trampoline_context_t *ctx, const rip_relative_t *rel, size_t insn_size)
{
    if (rel->size == 32) {
        if (*(int32_t*)(ctx->dst + rel->offset) != (uint32_t)rel->raddr) {
            /* sanity check.
             * reach here if opsiz and/or disp_offset are incorrectly
             * estimated.
             */
            funchook_set_error_message(ctx->funchook, "Invalid ip-relative offset %d. The value at the offset should be %08x but %08x",
                         rel->offset, (uint32_t)rel->raddr, *(int32_t*)(ctx->dst + rel->offset));
            return FUNCHOOK_ERROR_IP_RELATIVE_OFFSET;
        }
        ctx->rip_disp->disp[1].dst_addr = rel->addr;
        ctx->rip_disp->disp[1].src_addr_offset = (ctx->dst - ctx->dst_base) + insn_size;
        ctx->rip_disp->disp[1].pos_offset = (ctx->dst - ctx->dst_base) + rel->offset;
    } else if (rel->size != 0) {
        funchook_set_error_message(ctx->funchook, "Could not fix ip-relative address. The size is not 32.");
        return FUNCHOOK_ERROR_CANNOT_FIX_IP_RELATIVE;
    }
    return 0;
}

int funchook_fix_code(funchook_t *funchook, funchook_entry_t *entry, const ip_displacement_t *disp, const void *func, const void *hook_func)
{
    insn_t *src_addr;
    uint32_t *offset_addr;

#ifdef CPU_X86_64
    if (funchook_jump32_avail(func, hook_func)) {
        funchook_write_jump32(funchook, func, hook_func, entry->new_code);
        entry->transit[0] = 0;
    } else {
        funchook_write_jump32(funchook, func, entry->transit, entry->new_code);
        funchook_write_jump64(funchook, entry->transit, hook_func);
    }
#else
    funchook_write_jump32(funchook, func, hook_func, entry->new_code);
#endif
    /* fix rip-relative offsets */
    src_addr = entry->trampoline + disp->disp[0].src_addr_offset;
    offset_addr = (uint32_t*)(entry->trampoline + disp->disp[0].pos_offset);
    *offset_addr = (uint32_t)(disp->disp[0].dst_addr - src_addr);
    if (disp->disp[1].dst_addr != 0) {
        src_addr = entry->trampoline + disp->disp[1].src_addr_offset;
        offset_addr = (uint32_t*)(entry->trampoline + disp->disp[1].pos_offset);
        *offset_addr = (uint32_t)(disp->disp[1].dst_addr - src_addr);
    }
    return 0;
}

#ifdef CPU_X86_64
int funchook_page_avail(funchook_t *funchook, funchook_page_t *page, int idx, uint8_t *addr, ip_displacement_t *disp)
{
    funchook_entry_t *entry = &page->entries[idx];
    const uint8_t *src;
    const uint8_t *dst;

    if (!funchook_jump32_avail(addr, entry->trampoline)) {
        funchook_log(funchook, "  could not jump function %p to trampoline %p\n", addr, entry->trampoline);
        return 0;
    }
    src = entry->trampoline + disp->disp[0].src_addr_offset;
    dst = disp->disp[0].dst_addr;
    if (!funchook_within_32bit_relative(src, dst)) {
        funchook_log(funchook, "  could not jump trampoline %p to function %p\n",
                     src, dst);
        return 0;
    }
    src = entry->trampoline + disp->disp[1].src_addr_offset;
    dst = disp->disp[1].dst_addr;
    if (dst != 0 && !funchook_within_32bit_relative(src, dst)) {
        funchook_log(funchook, "  could not make 32-bit relative address from %p to %p\n",
                     src, dst);
        return 0;
    }
    return 1;
}
#endif
