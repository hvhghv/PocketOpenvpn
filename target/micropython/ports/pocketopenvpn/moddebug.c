#include "micropythonutil.h"
#include "py/lexer.h"
#include <stdio.h>

#define FL_PRINT (0x01)
#define FL_SPACE (0x02)
#define FL_DIGIT (0x04)
#define FL_ALPHA (0x08)
#define FL_UPPER (0x10)
#define FL_LOWER (0x20)
#define FL_XDIGIT (0x40)

#define AT_PR (FL_PRINT)
#define AT_SP (FL_SPACE | FL_PRINT)
#define AT_DI (FL_DIGIT | FL_PRINT | FL_XDIGIT)
#define AT_AL (FL_ALPHA | FL_PRINT)
#define AT_UP (FL_UPPER | FL_ALPHA | FL_PRINT)
#define AT_LO (FL_LOWER | FL_ALPHA | FL_PRINT)
#define AT_UX (FL_UPPER | FL_ALPHA | FL_PRINT | FL_XDIGIT)
#define AT_LX (FL_LOWER | FL_ALPHA | FL_PRINT | FL_XDIGIT)

static const uint8_t attr[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, AT_SP, AT_SP, AT_SP, AT_SP, AT_SP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, AT_SP, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_DI, AT_DI, AT_DI, AT_DI, AT_DI, AT_DI, AT_DI, AT_DI, AT_DI, AT_DI, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_UX, AT_UX, AT_UX, AT_UX, AT_UX, AT_UX, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_UP, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_PR, AT_LX, AT_LX, AT_LX, AT_LX, AT_LX, AT_LX, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_LO, AT_PR, AT_PR, AT_PR, AT_PR, 0};

bool unichar_isprint(unichar c) {
    return c < 128 && (attr[c] & FL_PRINT) != 0;
}

void mp_file_show_token(mp_lexer_t *lex) {

    while (lex->tok_kind != MP_TOKEN_END){

        printf("(" UINT_FMT ":" UINT_FMT ") kind:%u str:%p len:%zu", lex->tok_line, lex->tok_column, lex->tok_kind, lex->vstr.buf, lex->vstr.len);
        if (lex->vstr.len > 0) {
            const byte *i = (const byte *)lex->vstr.buf;
            const byte *j = (const byte *)i + lex->vstr.len;
            printf(" ");
            while (i < j) {
                unichar c = utf8_get_char(i);
                i         = utf8_next_char(i);
                if (unichar_isprint(c)) {
                    printf("%c", (int)c);
                } else {
                    printf("?");
                }
            }
        }

        printf("\n");

        mp_lexer_to_next(lex);
    }

}

MP_UTIL_REGISTER_FUNC(mp_file_show_token, 1) {

    const char *s = mp_obj_str_get_str(args[0]);
    qstr qs = qstr_from_str(s);
    mp_lexer_t *lex      = mp_lexer_new_from_file(qs);
    mp_file_show_token(lex);
    return mp_const_none;

}

MP_UTIL_REGISTER_MODULE_START(_d)
MP_UTIL_ADD_FUNC(tk, mp_file_show_token)
MP_UTIL_REGISTER_MODULE_END(_d)