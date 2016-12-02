/* -*- indent-tabs-mode: nil -*-
 *
 * printf_base - base function to make printf-like functions
 * https://github.com/kubo/printf_base
 *
 * Copyright (C) 2016 Kubo Takehiro <kubo@jiubao.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation
 * are those of the authors and should not be interpreted as representing
 * official policies, either expressed or implied, of the authors.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#ifdef WIN32
#include <malloc.h>
#ifndef alloca
#define alloca _alloca
#endif
#else
#include <alloca.h>
#endif
#include "printf_base.h"

#ifdef PFB_NO_EXTERNAL_FUNC
#ifndef PFB_NO_WIDE_CHAR_FORMAT
#define PFB_NO_WIDE_CHAR_FORMAT
#endif
#ifndef PFB_NO_FLOATING_POINT_FORMAT
#define PFB_NO_FLOATING_POINT_FORMAT
#endif
#endif

#ifndef PFB_NO_WIDE_CHAR_FORMAT
#include <wchar.h>
#endif
#ifndef PFB_NO_FLOATING_POINT_FORMAT
#include <math.h>
#endif

#ifdef __GNUC__
#ifndef HAVE_LONG_DOUBLE
#define HAVE_LONG_DOUBLE
#endif
#endif

#ifdef HAVE_LONG_DOUBLE
#define pfb_floor floorl
#define pfb_frexp frexpl
#define pfb_log10 log10l
#define pfb_pow powl
typedef long double pfb_double;
#else
#define pfb_floor floor
#define pfb_frexp frexp
#define pfb_log10 log10
#define pfb_pow pow
typedef double pfb_double;
#endif

#define PUTC(chr) do { \
    if (func(chr, handle) == -1) { \
        return -1; \
    } \
    outlen++; \
} while (0)

#define COND_PUTC(chr) do { \
    if (func && func(chr, handle) == -1) { \
        return -1; \
    } \
    outlen++; \
} while (0)

#define PUTC_N(chr, num) do { \
    int n = (num); \
    while (n-- > 0) { \
        PUTC(chr); \
    } \
} while (0)

#define COND_PUTC_N(chr, num) do { \
    int n = (num); \
    if (func) { \
        while (n-- > 0) { \
            PUTC(chr); \
        } \
    } else { \
        outlen += n; \
    } \
} while (0)

#define PUT_HEX(val) do { \
    int ival = (val); \
    if (ival < 10) { \
        PUTC(ival + '0'); \
    } else if (param->upper) { \
        PUTC((ival - 10) + 'A'); \
    } else { \
        PUTC((ival - 10) + 'a'); \
    } \
} while (0)

#define PUTS(ptr, len) do { \
    const char *p = (ptr); \
    const char *e = p + (len); \
    while (p < e) { \
        PUTC(*p); \
        p++; \
    } \
} while (0)

#ifdef PFB_NO_EXTERNAL_FUNC
static inline int pfb_strlen(const char *s)
{
    const char *t = s;
    while (*t) {
        t++;
    }
    return (int)(t - s);
}
#define strlen pfb_strlen
static inline void *pfb_memset(void *s, int c, size_t n)
{
    /* add volatile to suppress optimization to replace this function with memset by 'gcc -O3'. */
    char * volatile t = (char *)s;
    while (n-- > 0) {
        *(t++) = c;
    }
    return s;
}
#undef memset
#define memset pfb_memset
#endif

enum length_modifier {
    /*    */ LM_INT,
    /* hh */ LM_CHAR,
    /* h  */ LM_SHORT,
    /* l  */ LM_LONG,
    /* ll */ LM_LONGLONG,
    /* L  */ LM_LONGDOUBLE,
    /* j  */ LM_INTMAX_T,
    /* z  */ LM_SIZE_T,
    /* t  */ LM_PTRDIFF_T,
};

enum arg_type {
    AT_INT,
    AT_UINT,
    AT_DBL,
    AT_PTR,
};

typedef union {
    int64_t ival;
    uint64_t uival;
    pfb_double dbl;
    char *ptr;
} val_t;

typedef struct param {
    const char *begin_pos;
    const char *end_pos;
    /* flag characters */
    unsigned char alternate_form:1;
    unsigned char zero_padded:1;
    unsigned char left_adjusted:1;
    unsigned char blank:1;
    unsigned char add_sign:1;
    unsigned char thousands_grouping:1;
    /* other flags */
    unsigned char width_is_va_pos:1;
    unsigned char prec_is_va_pos:1;
    unsigned char prec_is_set:1;
    unsigned char upper:1;
    /* field width */
    int width;
    /* precision */
    int prec;
    /* length modifier */
    enum length_modifier lm;
    /* conversion_specifier */
    enum arg_type arg_type;
    int (*output_func)(pfb_putc_t func, void *handle, const struct param *param, int len);
    union {
        int va_pos;
        val_t val;
    } u;
} param_t;

#ifndef PFB_NO_WIDE_CHAR_FORMAT
static int is_wchar_length_modifier(enum length_modifier lm)
{
    switch (lm) {
    case LM_LONG:
    case LM_LONGLONG:
    case LM_LONGDOUBLE:
    case LM_INTMAX_T:
    case LM_SIZE_T:
    case LM_PTRDIFF_T:
        return 1;
    default:
        return 0;
    }
}
#endif

static int parse_format(const char *format, param_t *params, size_t num_param);
static int parse_one_param(const char **format, param_t *param, int *va_pos);
static int get_decimal(const char **str);
static int get_va_pos(const char **format);
static const char *parse_flag_characters(const char *format, param_t *param);
static const char *parse_field_width(const char *format, param_t *param);
static const char *parse_precision(const char *format, param_t *param);
static const char *parse_length_modifier(const char *format, param_t *param);
static const char *parse_conversion_specifier(const char *format, param_t *param);
static void fill_params(param_t *params, size_t num_param, va_list ap);
static int get_prec(const param_t *param, int default_prec);
static int get_zero_padded(const param_t *param);
static int output(pfb_putc_t func, void *handle, const char *format, const param_t *params, size_t num_param);
static int output_int(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_oct(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_uint(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_hex(pfb_putc_t func, void *handle, const param_t *param, int len);
#ifndef PFB_NO_FLOATING_POINT_FORMAT
static int output_edbl(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_fdbl(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_gdbl(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_adbl(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_no_finite_dbl(pfb_putc_t func, void *handle, const param_t *param);
#endif
static int output_chr(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_str(pfb_putc_t func, void *handle, const param_t *param, int len);
#ifndef PFB_NO_WIDE_CHAR_FORMAT
static int output_wch(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_wcs(pfb_putc_t func, void *handle, const param_t *param, int len);
#endif
static int output_ptr(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_num_written(pfb_putc_t func, void *handle, const param_t *param, int len);
static int output_percent_char(pfb_putc_t func, void *handle, const param_t *param, int len);

int printf_base(pfb_putc_t func, void *handle, const char *format, va_list ap)
{
    const char *fmt;
    int num_param = 0;
    param_t *params = NULL;

    for (fmt = format; *fmt != '\0'; fmt++) {
        if (*fmt == '%') {
            num_param++;
        }
    }
    if (num_param != 0) {
        size_t sz = num_param * sizeof(param_t);
        params = alloca(sz);
        memset(params, 0, sz);
        num_param = parse_format(format, params, num_param);
        fill_params(params, num_param, ap);
    }
    return output(func, handle, format, params, num_param);
}

typedef struct {
    pfb_write_t write;
    void *handle;
    int used;
    char buf[4096];
} write_arg_t;

static int write_func(int chr, write_arg_t *arg)
{
    if (arg->used == sizeof(arg->buf)) {
        if (arg->write(arg->handle, arg->buf, sizeof(arg->buf)) != sizeof(arg->buf)) {
            return -1;
        }
        arg->used = 0;
    }
    arg->buf[arg->used++] = chr;
    return 0;
}

int printf_base_with_buffering(pfb_write_t func, void *handle, const char *format, va_list ap)
{
    write_arg_t arg;
    int rv;

    arg.write = func;
    arg.handle = handle;
    arg.used = 0;
    rv = printf_base((pfb_putc_t)write_func, &arg, format, ap);
    if (rv == -1) {
        return -1;
    }
    if (func(handle, arg.buf, arg.used) != arg.used) {
        return -1;
    }
    return rv;
}

static int parse_format(const char *format, param_t *params, size_t num_param)
{
    int param_idx = 0;
    int va_pos = 1;

    while (*format != '\0') {
        if (*format == '%' && parse_one_param(&format, &params[param_idx], &va_pos) == 0) {
            param_idx++;
        } else {
            format++;
        }
    }
    return param_idx;
}

static int parse_one_param(const char **format, param_t *param, int *va_pos)
{
    const char *fmt = *format + 1;

    param->begin_pos = *format;
    param->u.va_pos = get_va_pos(&fmt);
    if ((fmt = parse_flag_characters(fmt, param)) == NULL) {
        return -1;
    }
    if ((fmt = parse_field_width(fmt, param)) == NULL) {
        return -1;
    }
    if ((fmt = parse_precision(fmt, param)) == NULL) {
        return -1;
    }
    if ((fmt = parse_length_modifier(fmt, param)) == NULL) {
        return -1;
    }
    if ((fmt = parse_conversion_specifier(fmt, param)) == NULL) {
        return -1;
    }
    if (param->width == 0 && param->width_is_va_pos) {
        param->width = (*va_pos)++;
    }
    if (param->prec == 0 && param->prec_is_va_pos) {
        param->prec = (*va_pos)++;
    }
    if (param->u.va_pos == 0) {
        param->u.va_pos = (*va_pos)++;
    }
    param->end_pos = *format = fmt;
    return 0;
}

static int get_decimal(const char **str)
{
    const char *s = *str;
    int num = 0;

    while ('0' <= *s && *s <= '9') {
        num *= 10;
        num += *(s++) - '0';
    }
    *str = s;
    return num;
}

static int get_va_pos(const char **format)
{
    const char *str = *format;
    int pos = get_decimal(&str);
    if (pos > 0 && *str == '$') {
        *format = str + 1;
        return pos;
    }
    return 0;
}

static const char *parse_flag_characters(const char *format, param_t *param)
{
    while (1) {
        switch (*format) {
        case '#':
            param->alternate_form = 1;
            break;
        case '0':
            param->zero_padded = 1;
            break;
        case '-':
            param->left_adjusted = 1;
            break;
        case ' ':
            param->blank = 1;
            break;
        case '+':
            param->add_sign = 1;
            break;
        case '\'':
            param->thousands_grouping = 1;
            break;
        default:
            return format;
        }
        format++;
    }
}

static const char *parse_field_width(const char *format, param_t *param)
{
    if (*format == '*') {
        format++;
        param->width = get_va_pos(&format);
        param->width_is_va_pos = 1;
        return format;
    }
    param->width = get_decimal(&format);
    return format;
}

static const char *parse_precision(const char *format, param_t *param)
{
    if (*format != '.') {
        return format;
    }
    param->prec_is_set = 1;
    format++;
    if (*format == '*') {
        format++;
        param->prec = get_va_pos(&format);
        param->prec_is_va_pos = 1;
        return format;
    }
    param->prec = get_decimal(&format);
    return format;
}

static const char *parse_length_modifier(const char *format, param_t *param)
{
    switch (format[0]) {
    case 'h':
        if (format[1] == 'h') {
            param->lm = LM_CHAR;
            return format + 2;
        } else {
            param->lm = LM_SHORT;
            return format + 1;
        }
    case 'l':
        if (format[1] == 'l') {
            param->lm = LM_LONGLONG;
            return format + 2;
        } else {
            param->lm = LM_LONG;
            return format + 1;
        }
    case 'L':
        param->lm = LM_LONGDOUBLE;
        return format + 1;
    case 'j':
        param->lm = LM_INTMAX_T;
        return format + 1;
    case 'z':
        param->lm = LM_SIZE_T;
        return format + 1;
    case 't':
        param->lm = LM_PTRDIFF_T;
        return format + 1;
#ifdef PFB_MSVC_FORMAT
    case 'w':
        param->lm = LM_LONG;
        return format + 1;
    case 'I':
        if (format[1] == '6' && format[2] == '4') {
            param->lm = LM_LONGLONG;
            return format + 3;
        }
        if (format[1] == '3' && format[2] == '2') {
            param->lm = LM_INT;
            return format + 3;
        }
        param->lm = LM_SIZE_T;
        return format + 1;
#endif
    }
    param->lm = LM_INT;
    return format;
}

static const char *parse_conversion_specifier(const char *format, param_t *param)
{
    switch (*format) {
    case 'd':
    case 'i':
        param->arg_type = AT_INT;
        param->output_func = output_int;
        return format + 1;
    case 'o':
        param->arg_type = AT_UINT;
        param->output_func = output_oct;
        return format + 1;
    case 'u':
        param->arg_type = AT_UINT;
        param->output_func = output_uint;
        return format + 1;
    case 'X':
        param->upper = 1;
        /* FALLTHROUGH */
    case 'x':
        param->arg_type = AT_UINT;
        param->output_func = output_hex;
        return format + 1;
#ifndef PFB_NO_FLOATING_POINT_FORMAT
    case 'E':
        param->upper = 1;
        /* FALLTHROUGH */
    case 'e':
        param->arg_type = AT_DBL;
        param->output_func = output_edbl;
        return format + 1;
    case 'F':
        param->upper = 1;
        /* FALLTHROUGH */
    case 'f':
        param->arg_type = AT_DBL;
        param->output_func = output_fdbl;
        return format + 1;
    case 'G':
        param->upper = 1;
        /* FALLTHROUGH */
    case 'g':
        param->arg_type = AT_DBL;
        param->output_func = output_gdbl;
        return format + 1;
    case 'A':
        param->upper = 1;
        /* FALLTHROUGH */
    case 'a':
        param->arg_type = AT_DBL;
        param->output_func = output_adbl;
        return format + 1;
#endif
#ifndef PFB_NO_WIDE_CHAR_FORMAT
    case 'C':
        param->lm = LM_LONG;
        /* FALLTHROUGH */
#endif
    case 'c':
        param->arg_type = AT_INT;
        param->output_func = output_chr;
#ifndef PFB_NO_WIDE_CHAR_FORMAT
        if (is_wchar_length_modifier(param->lm)) {
            param->output_func = output_wch;
        }
#endif
        return format + 1;
#ifndef PFB_NO_WIDE_CHAR_FORMAT
    case 'S':
        param->lm = LM_LONG;
        /* FALLTHROUGH */
#endif
    case 's':
        param->arg_type = AT_PTR;
        param->output_func = output_str;
#ifndef PFB_NO_WIDE_CHAR_FORMAT
        if (is_wchar_length_modifier(param->lm)) {
            param->output_func = output_wcs;
        }
#endif
        return format + 1;
    case 'p':
        param->lm = LM_SIZE_T;
        param->arg_type = AT_UINT;
        param->output_func = output_ptr;
        return format + 1;
    case 'n':
        param->arg_type = AT_PTR;
        param->output_func = output_num_written;
        return format + 1;
    case '%':
        param->output_func = output_percent_char;
        param->u.va_pos = -1;
        return format + 1;
    }
    return NULL;
}

static void fill_params(param_t *params, size_t num_param, va_list ap)
{
    param_t *param, *param_end = params + num_param;
    int max_pos = 0;
    int i;
    val_t *vals;

    for (param = params; param < param_end; param++) {
        if (max_pos < param->u.va_pos) {
            max_pos = param->u.va_pos;
        }
        if (param->width_is_va_pos && max_pos < param->width) {
            max_pos = param->width;
        }
        if (param->prec_is_va_pos && max_pos < param->prec) {
            max_pos = param->prec;
        }
    }
    vals = alloca(max_pos *  sizeof(val_t));
    memset(vals, 0, max_pos *  sizeof(val_t));
    for (i = 0; i < max_pos; i++) {
        for (param = params; param < param_end; param++) {
            if (param->u.va_pos == i + 1) {
                switch (param->arg_type) {
                case AT_INT:
                    switch (param->lm) {
                    case LM_INT:
                        vals[i].ival = va_arg(ap, int);
                        break;
                    case LM_CHAR:
                        vals[i].ival = (char)va_arg(ap, int);
                        break;
                    case LM_SHORT:
                        vals[i].ival = (short)va_arg(ap, int);
                        break;
                    case LM_LONG:
                        vals[i].ival = va_arg(ap, long);
                        break;
                    case LM_LONGLONG:
                        vals[i].ival = va_arg(ap, int64_t);
                        break;
                    case LM_LONGDOUBLE:
                        vals[i].ival = va_arg(ap, long);
                        break;
                    case LM_INTMAX_T:
                        vals[i].ival = va_arg(ap, intmax_t);
                        break;
                    case LM_SIZE_T:
                        vals[i].ival = va_arg(ap, intptr_t);
                        break;
                    case LM_PTRDIFF_T:
                        vals[i].ival = va_arg(ap, ptrdiff_t);
                        break;
                    }
                    break;
                case AT_UINT:
                    switch (param->lm) {
                    case LM_INT:
                        vals[i].uival = va_arg(ap, unsigned int);
                        break;
                    case LM_CHAR:
                        vals[i].uival = (unsigned char)va_arg(ap, unsigned int);
                        break;
                    case LM_SHORT:
                        vals[i].uival = (unsigned short)va_arg(ap, unsigned int);
                        break;
                    case LM_LONG:
                        vals[i].uival = va_arg(ap, unsigned long);
                        break;
                    case LM_LONGLONG:
                        vals[i].uival = va_arg(ap, uint64_t);
                        break;
                    case LM_LONGDOUBLE:
                        vals[i].uival = va_arg(ap, unsigned long);
                        break;
                    case LM_INTMAX_T:
                        vals[i].uival = va_arg(ap, uintmax_t);
                        break;
                    case LM_SIZE_T:
                        vals[i].uival = va_arg(ap, uintptr_t);
                        break;
                    case LM_PTRDIFF_T:
                        vals[i].uival = va_arg(ap, ptrdiff_t);
                        break;
                    }
                    break;
                case AT_DBL:
                    switch (param->lm) {
                    case LM_LONGLONG:
                    case LM_LONGDOUBLE:
                        vals[i].dbl = va_arg(ap, pfb_double);
                        break;
                    default:
                        vals[i].dbl = va_arg(ap, double);
                        break;
                    }
                    break;
                case AT_PTR:
                    vals[i].ptr = va_arg(ap, void *);
                    break;
                }
                break;
            } else if (param->width_is_va_pos && param->width == i + 1) {
                param->width = va_arg(ap, int);
                if (param->width < 0) {
                    param->left_adjusted = 1;
                    param->width = -param->width;
                }
                break;
            } else if (param->prec_is_va_pos && param->prec == i + 1) {
                param->prec = va_arg(ap, int);
                break;
            }
        }
        if (param == param_end) {
            va_arg(ap, int); /* skip this argument */
        }
    }
    for (param = params; param < param_end; param++) {
        if (param->u.va_pos > 0) {
            param->u.val = vals[param->u.va_pos - 1];
        }
    }
}

static int get_prec(const param_t *param, int default_prec)
{
    if (!param->prec_is_set) {
        return default_prec;
    } else if (param->prec > 0) {
        return param->prec;
    } else {
        return 0;
    }
}

static int get_zero_padded(const param_t *param)
{
    if (param->prec_is_set) {
        return 0;
    } else {
        return param->zero_padded;
    }
}

static int output(pfb_putc_t func, void *handle, const char *format, const param_t *params, size_t num_param)
{
    const char *last_pos = format;
    int outlen = 0;
    size_t i;

    for (i = 0; i < num_param; i++) {
        const param_t *param = &params[i];
        int rv;

        while (last_pos < param->begin_pos) {
            PUTC(*(last_pos++));
        }
        rv = param->output_func(func, handle, param, outlen);
        if (rv == -1) {
            return rv;
        }
        outlen += rv;
        last_pos = param->end_pos;
    }
    while (*last_pos) {
        PUTC(*(last_pos++));
    }
    return outlen;
}

static int output_int(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    char buf[30];
    int64_t ival = param->u.val.ival;
    int prec = get_prec(param, 1);
    int zero_padded = get_zero_padded(param);
    int outlen = 0;
    int datalen;
    int bufused;
    char sign = 0;
    int padding_len;
    int i;

    if (ival < 0) {
        ival = -ival;
        sign = '-';
    } else if (param->add_sign) {
        sign = '+';
    } else if (param->blank) {
        sign = ' ';
    }
    if (ival == 0 && prec == 0) {
        i = sizeof(buf);
    } else {
        for (i = sizeof(buf) - 1; i >= 0; i--) {
            buf[i] = (ival % 10) + '0';
            ival /= 10;
            if (ival == 0) {
                break;
            }
        }
    }
    bufused = sizeof(buf) - i;
    /* calculate padding length */
    datalen = bufused;
    if (datalen < prec) {
        datalen = prec;
    }
    if (sign) {
        datalen++;
    }
    padding_len = param->width - datalen;
    /* put characters */
    if (!param->left_adjusted && !zero_padded) {
        PUTC_N(' ', padding_len);
    }
    if (sign) {
        PUTC(sign);
    }
    if (!param->left_adjusted && zero_padded) {
        PUTC_N('0', padding_len);
    }
    PUTC_N('0', prec - bufused);
    PUTS(buf + i, bufused);
    if (param->left_adjusted) {
        PUTC_N(' ', padding_len);
    }
    return outlen;
}

static int output_oct(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    char buf[30];
    int64_t uival = param->u.val.uival;
    int prec = get_prec(param, 1);
    int zero_padded = get_zero_padded(param);
    int outlen = 0;
    int datalen;
    int bufused;
    int padding_len;
    int i;

    if (uival == 0) {
        i = sizeof(buf);
        if (param->alternate_form || prec != 0) {
            buf[--i] = '0';
        }
    } else {
        for (i = sizeof(buf) - 1; i >= 0; i--) {
            buf[i] = (uival & 7) + '0';
            uival >>= 3;
            if (uival == 0) {
                break;
            }
        }
        if (param->alternate_form) {
            buf[--i] = '0';
        }
    }
    bufused = sizeof(buf) - i;
    /* calculate padding length */
    datalen = bufused;
    if (datalen < prec) {
        datalen = prec;
    }
    padding_len = param->width - datalen;
    /* put characters */
    if (!param->left_adjusted) {
        if (zero_padded) {
            PUTC_N('0', padding_len);
        } else {
            PUTC_N(' ', padding_len);
        }
    }
    PUTC_N('0', prec - bufused);
    PUTS(buf + i, bufused);
    if (param->left_adjusted) {
        PUTC_N(' ', padding_len);
    }
    return outlen;
}

static int output_uint(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    char buf[30];
    int64_t uival = param->u.val.uival;
    int prec = get_prec(param, 1);
    int zero_padded = get_zero_padded(param);
    int outlen = 0;
    int datalen;
    int bufused;
    int padding_len;
    int i;

    if (uival == 0) {
        i = sizeof(buf);
        if (prec != 0) {
            buf[--i] = '0';
        }
    } else {
        for (i = sizeof(buf) - 1; i >= 0; i--) {
            buf[i] = (uival % 10) + '0';
            uival /= 10;
            if (uival == 0) {
                break;
            }
        }
    }
    bufused = sizeof(buf) - i;
    /* calculate padding length */
    datalen = bufused;
    if (datalen < prec) {
        datalen = prec;
    }
    padding_len = param->width - datalen;
    /* put characters */
    if (!param->left_adjusted) {
        if (zero_padded) {
            PUTC_N('0', padding_len);
        } else {
            PUTC_N(' ', padding_len);
        }
    }
    PUTC_N('0', prec - bufused);
    PUTS(buf + i, bufused);
    if (param->left_adjusted) {
        PUTC_N(' ', padding_len);
    }
    return outlen;
}

static int output_hex(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    char buf[30];
    int64_t uival = param->u.val.uival;
    int prec = get_prec(param, 1);
    int zero_padded = get_zero_padded(param);
    char alternate_form = param->alternate_form;
    int outlen = 0;
    int datalen;
    int bufused;
    int padding_len;
    int i;

    if (uival == 0) {
        i = sizeof(buf);
        if (prec != 0) {
            buf[--i] = '0';
        }
        alternate_form = 0;
    } else {
        for (i = sizeof(buf) - 1; i >= 0; i--) {
            if ((uival & 0xf) < 10) {
                buf[i] = (uival & 0xf) + '0';
            } else {
                buf[i] = (uival & 0xf) - 10 + ((param->upper) ? 'A' : 'a');
            }
            uival >>= 4;
            if (uival == 0) {
                break;
            }
        }
    }
    bufused = sizeof(buf) - i;
    /* calculate padding length */
    datalen = bufused;
    if (datalen < prec) {
        datalen = prec;
    }
    if (alternate_form) {
        datalen += 2;
    }
    padding_len = param->width - datalen;
    /* put characters */
    if (!param->left_adjusted && !zero_padded) {
        PUTC_N(' ', padding_len);
    }
    if (alternate_form) {
        PUTC('0');
        PUTC((param->upper) ? 'X' : 'x');
    }
    if (!param->left_adjusted && zero_padded) {
        PUTC_N('0', padding_len);
    }
    PUTC_N('0', prec - bufused);
    PUTS(buf + i, bufused);
    if (param->left_adjusted) {
        PUTC_N(' ', padding_len);
    }
    return outlen;
}

#ifndef PFB_NO_FLOATING_POINT_FORMAT
static int output_edbl(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    pfb_double dbl = param->u.val.dbl;
    int prec = get_prec(param, 6);
    int outlen = 0;
    int exp = 0;
    char sign = 0;
    int padding_len;

    if (!isfinite(dbl)) {
        return output_no_finite_dbl(func, handle, param);
    }
    if (signbit(dbl)) {
        dbl = -dbl;
        sign = '-';
    } else if (param->add_sign) {
        sign = '+';
    } else if (param->blank) {
        sign = ' ';
    }
    padding_len = param->width - (prec + 5);
    if (dbl != 0.0) {
        while (dbl >= 10.0) {
            dbl /= 10.0;
            exp++;
        }
        while (dbl < 1.0) {
            dbl *= 10.0;
            exp--;
        }
        dbl += 0.5 * pfb_pow(0.1, prec);
    } else {
        dbl = 0.0;
        exp = 0;
    }
    if (prec > 0 || param->alternate_form) {
        padding_len--;
    }
    if (sign) {
        padding_len--;
    }
    /* put characters */
    if (!param->left_adjusted && !param->zero_padded) {
        PUTC_N(' ', padding_len);
    }
    if (sign) {
        PUTC(sign);
    }
    if (!param->left_adjusted && param->zero_padded) {
        PUTC_N('0', padding_len);
    }
    PUTC((int)dbl + '0');
    if (prec > 0 || param->alternate_form) {
        PUTC('.');
    }
    while (prec-- > 0) {
        pfb_double intpart = pfb_floor(dbl);
        dbl -= intpart;
        dbl *= 10.0;
        PUTC((int)dbl + '0');
    }
    PUTC(param->upper ? 'E' : 'e');
    if (exp >= 0) {
        PUTC('+');
    } else {
        PUTC('-');
        exp = -exp;
    }
    PUTC((exp / 10) + '0');
    PUTC((exp % 10) + '0');
    if (param->left_adjusted) {
        PUTC_N(' ', padding_len);
    }
    return outlen;
}

static int output_fdbl(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    pfb_double dbl = param->u.val.dbl;
    int prec = get_prec(param, 6);
    pfb_double intpart = 0.0;
    pfb_double d = 10.0;
    int ilen = 1; /* length of integer part */
    int datalen;
    int outlen = 0;
    int padding_len;
    char sign = 0;

    if (!isfinite(dbl)) {
        return output_no_finite_dbl(func, handle, param);
    }
    if (signbit(dbl)) {
        dbl = -dbl;
        sign = '-';
    } else if (param->add_sign) {
        sign = '+';
    } else if (param->blank) {
        sign = ' ';
    }
    if (dbl != 0.0) {
        if (prec > 0) {
            dbl += 0.5 * pfb_pow(0.1, prec);
        }
        intpart = pfb_floor(dbl);
        while (dbl >= d) {
            d *= 10.0;
            ilen++;
        }
    }
    datalen = ilen + prec;
    if (sign) {
        datalen++;
    }
    if (prec || param->alternate_form) {
        datalen++; /* dot */
    }
    padding_len = param->width - datalen;
    /* put characters */
    if (!param->left_adjusted && !param->zero_padded) {
        PUTC_N(' ', padding_len);
    }
    if (sign) {
        PUTC(sign);
    }
    if (!param->left_adjusted && param->zero_padded) {
        PUTC_N('0', padding_len);
    }
    d /= 10.0;
    while (ilen-- > 0) {
        pfb_double top_dec = pfb_floor(intpart / d);
        PUTC((int)top_dec + '0');
        intpart -= top_dec * d;
        d /= 10.0;
    }
    if (prec || param->alternate_form) {
        PUTC('.');
    }
    while (prec-- > 0) {
        intpart = pfb_floor(dbl);
        dbl -= intpart;
        dbl *= 10.0;
        PUTC((int)dbl + '0');
    }
    if (param->left_adjusted) {
        PUTC_N(' ', padding_len);
    }
    return outlen;
}

static inline int out_gdbl(pfb_putc_t func, void *handle, const param_t *param, pfb_double intpart, pfb_double fracpart, int ilen, int flen, int exp)
{
    int outlen = 0;
    int num_zeros = 0;
    int dot = 0;
    if (ilen == 1) {
        COND_PUTC((int)intpart + '0');
    } else {
        pfb_double d = pfb_pow(10.0, ilen - 1);
        do {
            int ival = (int)(intpart / d);
            COND_PUTC(ival + '0');
            intpart -= ival * d;
            d /= 10.0;
        } while (d >= 1.0);
    }
    fracpart *= 10.0;
    while (flen-- > 0) {
        int ival = (int)fracpart;
        if (ival == 0) {
            num_zeros++;
        } else {
            if (!dot) {
                COND_PUTC('.');
                dot = 1;
            }
            if (num_zeros) {
                COND_PUTC_N('0', num_zeros);
                num_zeros = 0;
            }
            COND_PUTC(ival + '0');
        }
        fracpart -= ival;
        fracpart *= 10.0;
    }
    if (param->alternate_form) {
        if (!dot) {
            COND_PUTC('.');
        }
        if (num_zeros) {
            COND_PUTC_N('0', num_zeros);
        }
    }
    if (exp) {
        COND_PUTC(param->upper ? 'E' : 'e');
        if (exp > 0) {
            COND_PUTC('+');
        } else {
            COND_PUTC('-');
            exp = -exp;
        }
        COND_PUTC((exp / 10) + '0');
        COND_PUTC((exp % 10) + '0');
    }
    return outlen;
}

static int output_gdbl(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    pfb_double dbl = param->u.val.dbl;
    int prec = get_prec(param, 6);
    int outlen = 0;
    pfb_double intpart;
    pfb_double fracpart;
    int ilen; /* length of integer part */
    int flen; /* length of fractional part */
    int exp = 0;
    int padding_len;
    char sign = 0;
    int rv;

    if (!isfinite(dbl)) {
        return output_no_finite_dbl(func, handle, param);
    }
    if (prec == 0) {
        prec = 1;
    }
    if (signbit(dbl)) {
        dbl = -dbl;
        sign = '-';
    } else if (param->add_sign) {
        sign = '+';
    } else if (param->blank) {
        sign = ' ';
    }
    if (dbl != 0.0) {
        exp = (int)pfb_floor(pfb_log10(dbl));
        dbl += pfb_pow(10.0, exp - prec + 1) / 2;
        if (dbl >= pfb_pow(10.0, exp + 1)) {
            exp++;
        }

        if (exp < -4 || exp > prec) {
            dbl /= pfb_pow(10.0, exp);
            ilen = 1;
            flen = prec - 1;
        } else {
            if (exp >= 0) {
                ilen = exp + 1;
                flen = prec - ilen;
            } else {
                ilen = 1;
                flen = prec - exp - 1;
            }
            exp = 0;
        }
        intpart = pfb_floor(dbl);
        fracpart = dbl - intpart;
    } else {
        intpart = 0.0;
        fracpart = 0.0;
        ilen = 0;
        flen = prec - 1;
        exp = 0;
    }
    padding_len = param->width - out_gdbl(NULL, NULL, param, intpart, fracpart, ilen, flen, exp);
    if (sign) {
        padding_len--;
    }
    /* put characters */
    if (!param->left_adjusted && !param->zero_padded) {
        PUTC_N(' ', padding_len);
    }
    if (sign) {
        PUTC(sign);
    }
    if (!param->left_adjusted && param->zero_padded) {
        PUTC_N('0', padding_len);
    }
    rv = out_gdbl(func, handle, param, intpart, fracpart, ilen, flen, exp);
    if (rv == -1) {
        return rv;
    }
    outlen += rv;
    if (param->left_adjusted) {
        PUTC_N(' ', padding_len);
    }
    return outlen;
}

static int output_adbl(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    pfb_double dbl = param->u.val.dbl;
    int prec = get_prec(param, 6);
    int outlen = 0;
    int exp;
    char exp_sign;
    char sign = 0;
    int padding_len;

    if (!isfinite(dbl)) {
        return output_no_finite_dbl(func, handle, param);
    }
    if (signbit(dbl)) {
        dbl = -dbl;
        sign = '-';
    } else if (param->add_sign) {
        sign = '+';
    } else if (param->blank) {
        sign = ' ';
    }
    padding_len = param->width - (prec + 6);
    dbl = pfb_frexp(dbl, &exp);
    if (dbl != 0.0) {
        switch (param->lm) {
        case LM_LONGLONG:
        case LM_LONGDOUBLE:
            dbl *= (1 << 4);
            exp -= 4;
            break;
        default:
            dbl *= (1 << 1);
            exp -= 1;
            break;
        }
        dbl += 0.5 * pfb_pow(0.0625, prec);
    }
    if (exp >= 0) {
        exp_sign = '+';
    } else {
        exp = - exp;
        exp_sign = '-';
    }
    if (exp > 10) {
        padding_len--;
    }
    if (prec > 0 || param->alternate_form) {
        padding_len--;
    }
    if (sign) {
        padding_len--;
    }
    /* put characters */
    if (!param->left_adjusted && !param->zero_padded) {
        PUTC_N(' ', padding_len);
    }
    if (sign) {
        PUTC(sign);
    }
    PUTC('0');
    PUTC(param->upper ? 'X' : 'x');
    if (!param->left_adjusted && param->zero_padded) {
        PUTC_N('0', padding_len);
    }
    PUT_HEX((int)dbl);
    if (prec > 0) {
        PUTC('.');
        while (prec-- > 0) {
            pfb_double intpart = pfb_floor(dbl);
            dbl -= intpart;
            dbl *= 16.0;
            PUT_HEX((int)dbl);
        }
    } else if (param->alternate_form) {
        PUTC('.');
    }
    PUTC(param->upper ? 'P' : 'p');
    PUTC(exp_sign);
    if (exp < 10) {
        PUTC(exp + '0');
    } else {
        PUTC((exp / 10) + '0');
        PUTC((exp % 10) + '0');
    }
    if (param->left_adjusted) {
        PUTC_N(' ', padding_len);
    }
    return outlen;
}

static int output_no_finite_dbl(pfb_putc_t func, void *handle, const param_t *param)
{
    pfb_double dbl = param->u.val.dbl;
    int outlen = 0;
    const char *str;
    size_t slen;
    int padding_len;
    char sign = 0;

    if (signbit(dbl)) {
        sign = '-';
    } else if (param->add_sign) {
        sign = '+';
    } else if (param->blank) {
        sign = ' ';
    }
    if (isnan(dbl)) {
        str = param->upper ? "NAN" : "nan";
        slen = 3;
    } else {
        str = param->upper ? "INF" : "inf";
        slen = 3;
    }
    padding_len = (int)(param->width - slen);
    if (sign) {
        padding_len--;
    }
    /* put characters */
    if (!param->left_adjusted) {
        PUTC_N(' ', padding_len);
    }
    if (sign) {
        PUTC(sign);
    }
    PUTS(str, slen);
    if (param->left_adjusted) {
        PUTC_N(' ', padding_len);
    }
    return outlen;
}
#endif

static int output_chr(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    int outlen = 0;
    if (!param->left_adjusted) {
        PUTC_N(' ', param->width - 1);
    }
    PUTC((char)param->u.val.ival);
    if (param->left_adjusted) {
        PUTC_N(' ', param->width - 1);
    }
    return outlen;
}

static int output_str(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    const char *str = param->u.val.ptr;
    size_t slen = 0;
    int outlen = 0;

    if (str == NULL) {
        if (param->prec_is_set && param->prec < 6) {
            str = "";
            slen = 0;
        } else {
            str = "(null)";
            slen = 6;
        }
    } else {
        if (param->prec_is_set) {
            for (slen = 0; str[slen] != 0; slen++) {
                if (slen == (size_t)param->prec) {
                    break;
                }
            }
        } else {
            slen = strlen(str);
        }
    }
    if (!param->left_adjusted) {
        PUTC_N(' ', (int)(param->width - slen));
    }
    PUTS(str, slen);
    if (param->left_adjusted) {
        PUTC_N(' ', (int)(param->width - slen));
    }
    return outlen;
}

#ifndef PFB_NO_WIDE_CHAR_FORMAT
static int output_wcs(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    const wchar_t *wcs = (const wchar_t *)param->u.val.ptr;
    char *str;
    size_t slen;
    int outlen = 0;
    int use_malloc = 0;

    if (wcs == NULL) {
        if (param->prec_is_set && param->prec < 6) {
            str = "";
            slen = 0;
        } else {
            str = "(null)";
            slen = 6;
        }
    } else {
        mbstate_t mbstate;
        size_t wlen;
        size_t prec = SIZE_MAX;
        size_t sz;
        int i;

        if (param->prec_is_set) {
            if (param->prec > 0) {
                prec = (size_t)param->prec;
            } else {
                prec = 0;
            }
        }
        for (wlen = 0; wcs[wlen] != 0; wlen++) {
            if (wlen == prec) {
                break;
            }
        }
        if (wlen > 4096) {
            str = malloc(4 * wlen);
            if (str == NULL) {
                return -1;
            }
            use_malloc = 1;
        } else {
            str = alloca(4 * wlen);
        }
        slen = 0;
        memset(&mbstate, 0, sizeof(mbstate_t));
        for (i = 0; i < wlen; i++) {
            sz = wcrtomb(str + slen, wcs[i], &mbstate);
            if (sz != (size_t)-1) {
                if (slen + sz > prec) {
                    break;
                }
                slen += sz;
                if (slen == prec) {
                    break;
                }
            }
        }
        if (i == wlen) {
            sz = wcrtomb(str + slen, L'\0', &mbstate);
            if (sz != (size_t)-1) {
                while (sz > 0 && str[slen + sz - 1] == '\0') {
                    sz--;
                }
                if (slen + sz <= prec) {
                    slen += sz;
                }
            }
        }
    }
    if (!param->left_adjusted) {
        PUTC_N(' ', (int)(param->width - slen));
    }
    PUTS(str, slen);
    if (param->left_adjusted) {
        PUTC_N(' ', (int)(param->width - slen));
    }
    if (use_malloc) {
        free(str);
    }
    return outlen;
}

static int output_wch(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    wchar_t wch = (wchar_t)param->u.val.ival;
    mbstate_t mbstate;
    char str[10];
    size_t slen;
    int outlen = 0;

    memset(&mbstate, 0, sizeof(mbstate_t));
    slen = wcrtomb(str, wch, &mbstate);
    if (slen != (size_t)-1) {
        while (slen > 0 && str[slen - 1] == '\0') {
            slen--;
        }
    } else {
        slen = 0;
    }
    if (!param->left_adjusted) {
        PUTC_N(' ', (int)(param->width - slen));
    }
    PUTS(str, slen);
    if (param->left_adjusted) {
        PUTC_N(' ', (int)(param->width - slen));
    }
    return outlen;
}
#endif

static int output_ptr(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    char buf[30];
    int64_t uival = param->u.val.uival;
    int i;
    int prec;
    int outlen = 0;
    int datalen;
    int bufused;
    char sign = 0;

    if (uival == 0) {
        if (!param->left_adjusted) {
            PUTC_N(' ', param->width - 5);
        }
        PUTS("(nil)", 5);
        if (param->left_adjusted) {
            PUTC_N(' ', param->width - 5);
        }
        return outlen;
    }

    if (param->add_sign) {
        sign = '+';
    } else if (param->blank) {
        sign = ' ';
    }

    for (i = sizeof(buf) - 1; i >= 0; i--) {
        if ((uival & 0xf) < 10) {
            buf[i] = (uival & 0xf) + '0';
        } else {
            buf[i] = (uival & 0xf) - 10 + ((param->upper) ? 'A' : 'a');
        }
        uival >>= 4;
        if (uival == 0) {
          break;
        }
    }
    bufused = sizeof(buf) - i;
    /* calculate padding length */
    prec = bufused;
    if (param->prec_is_set && prec < param->prec) {
        prec = param->prec;
    }
    datalen = prec + 2;
    if (sign) {
        datalen++;
    }
    /* put characters */
    if (!param->left_adjusted) {
        PUTC_N(' ', param->width - datalen);
    }
    if (sign) {
        PUTC(sign);
    }
    PUTC('0');
    PUTC((param->upper) ? 'X' : 'x');
    PUTC_N('0', prec - bufused);
    PUTS(buf + i, bufused);
    if (param->left_adjusted) {
        PUTC_N(' ', param->width - datalen);
    }
    return outlen;
}

static int output_num_written(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    const char *addr = param->u.val.ptr;
    switch (param->lm) {
    case LM_CHAR:
        *(unsigned char*)addr = len;
        break;
    case LM_SHORT:
        *(unsigned short*)addr = len;
        break;
    case LM_LONG:
        *(long*)addr = len;
        break;
    case LM_LONGLONG:
        *(int64_t*)addr = len;
        break;
    case LM_INTMAX_T:
        *(intmax_t*)addr = len;
        break;
    case LM_SIZE_T:
        *(size_t*)addr = len;
        break;
    case LM_PTRDIFF_T:
        *(ptrdiff_t*)addr = len;
        break;
    default:
        *(int*)addr = len;
        break;
    }
    return 0;
}

static int output_percent_char(pfb_putc_t func, void *handle, const param_t *param, int len)
{
    int outlen = 0;
    PUTC('%');
    return outlen;
}
