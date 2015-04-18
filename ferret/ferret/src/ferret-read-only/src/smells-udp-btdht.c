#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#ifndef UNUSEDPARM
#define UNUSEDPARM(x) (void)x
#endif
#if defined(_MSC_VER) && !defined(inline)
#define inline __inline
#endif

enum BenType {
    Ben_Unknown,
    Ben_Integer,
    Ben_String,
};

struct BenDecode
{
    unsigned char state;
    unsigned char keyname_offset;
    unsigned char keyname_length;
    unsigned char is_extract:1;
    unsigned len;
    const char *keyname;
    unsigned list_index;
    unsigned ben_type;

    unsigned char *value;
    size_t value_max;
    size_t value_length;

    int64_t number;
    unsigned is_negative:1;

    struct {
        unsigned index;
        struct {
            unsigned char state;
            unsigned char keyname_offset;
            unsigned char keyname_length;
            unsigned char is_extract:1;
        } list[256];
    } depth;
};

static inline unsigned
ben_push(struct BenDecode *ben)
{
    if (ben->depth.index >= sizeof(ben->depth.list)/sizeof(ben->depth.list[0]))
        return 1;
    ben->depth.list[ben->depth.index].state = ben->state;
    ben->depth.list[ben->depth.index].is_extract = ben->is_extract;
    ben->depth.list[ben->depth.index].keyname_offset = ben->keyname_offset;
    ben->depth.list[ben->depth.index].keyname_length = ben->keyname_length;
    ben->depth.index++;
    return 0;
}
static inline void
ben_pop(struct BenDecode *ben)
{
    if (ben->depth.index == 0) {
        ben->state = ~0;
        return;
    }
    ben->depth.index--;
    ben->state = ben->depth.list[ben->depth.index].state;
    ben->is_extract = ben->depth.list[ben->depth.index].is_extract;
    ben->keyname_offset = ben->depth.list[ben->depth.index].keyname_offset;
    ben->keyname_length = ben->depth.list[ben->depth.index].keyname_length;

}

static void
bendecode_init(struct BenDecode *ben,
    const char *keyname, enum BenType bentype,
    unsigned char *value, size_t sizeof_value)
{
    memset(ben, 0, sizeof(*ben));

    ben->keyname = keyname;
    ben->keyname_length = (unsigned char)strlen(keyname);
    ben->ben_type = bentype;
    ben->value_max = sizeof_value;
    ben->value = value;
    ben->is_extract = 1;
    ben->depth.index = 0;
}

/*
   dictionary = "d" 1*(string anytype) "e" ; non-empty dictionary
   list       = "l" 1*anytype "e"          ; non-empty list
   integer    = "i" signumber "e"
   string     = number ":" <number long sequence of any CHAR>
   anytype    = dictionary / list / integer / string
   signumber  = "-" number / number
   number     = 1*DIGIT
   CHAR       = %x00-FF                    ; any 8-bit character
   DIGIT      = "0" / "1" / "2" / "3" / "4" /
                "5" / "6" / "7" / "8" / "9"
*/
static unsigned
bendecode(
        struct BenDecode *ben,
        const unsigned char *px, unsigned length
        )
{
    unsigned i;
    enum {
        ANYTYPE, 
        DICT, 
        DICT_KEY_LEN,
        DICT_KEY_MATCH,
        LIST, 
        INTEGER, INTEGER_DIGIT,
        STRING, STRING_DIGIT, STRING_CHAR,
    };

    for (i=0; i<length; i++)
    switch (ben->state) {
    case ANYTYPE:
anytype:
        switch (px[i]) {
        case 'd':
            ben->state = DICT;
            break;
        case 'l':
            ben->state = LIST;
            break;
        case 'i':
            ben->state = INTEGER;
            break;
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            ben->state = STRING;
            i--;
            break;
        default:
            /* unknown */
            ben->state = ~0;
            i = length;
            break;
        }
        break;

    case INTEGER:
        ben->state = INTEGER_DIGIT;
        ben->number = 0;
        if (px[i] == '-') {
            ben->is_negative = 1;
            continue;
        } else {
            ben->is_negative = 0;
        }
        /*fall through*/

    case INTEGER_DIGIT:
        if (px[i] == 'e') {
            if (ben->is_negative)
                ben->number = 0 - ben->number;
            if (ben->is_extract) {
                *(int64_t*)ben->value = ben->number;
                ben->value_length = sizeof(int64_t);
                return 1;
            }
            ben_pop(ben);
        } else if (isdigit(px[i])) {
            ben->number *= 10;
            ben->number += px[i] - '0';
        } else {
            ben->state = ~0;
        }
        break;

    case STRING:
        ben->state = STRING_DIGIT;
        ben->number = 0;
        /* fall through */

    case STRING_DIGIT:
        if (px[i] == ':') {
            if (ben->number == 0) {
                if (ben->is_extract) {
                    ben->value_length = 0;
                    return 1;
                }
                ben_pop(ben);
            } else {
                ben->state = STRING_CHAR;
            }
        } else if (isdigit(px[i])) {
            ben->number *= 10;
            ben->number += px[i] - '0';
        } else {
            ben->state = ~0;
        }
        break;

    case STRING_CHAR:
        if (ben->is_extract) {
            if (ben->value_length < ben->value_max) {
                ben->value[ben->value_length++] = px[i];
            }
        }
        ben->number--;
        if (ben->number == 0) {
            if (ben->is_extract) {
                return 1;
            }
            ben_pop(ben);
        } else {
            ben->state = STRING_CHAR;
        }
        break;

    case LIST:
        if (px[i] == 'e') {
            ben_pop(ben);
        } else {
            ben_push(ben);
            if (ben->keyname[ben->keyname_offset] == '\0') {
                if (ben->list_index == 0)
                    ;
                else {
                    ben->is_extract = 0;
                    ben->list_index--;
                }
            }
            ben->state = ANYTYPE;
            goto anytype;
        }
        break;




    case DICT:
        if (px[i] == 'e') {
            ben_pop(ben);
        } else {
            i--;
            ben_push(ben);
            ben->keyname_offset += ben->keyname_length + 1;
            ben->keyname_length = strlen(ben->keyname + ben->keyname_offset);
            ben->state = DICT_KEY_LEN;
            ben->number = 0;
        }
        continue;

    case DICT_KEY_LEN:
        if (px[i] == ':') {
            if (ben->number == 0) {
                if (ben->keyname_length != 0)
                    ben->is_extract = 0;
                ben->state = ANYTYPE;
            } else if (ben->number != ben->keyname_length) {
                ben->is_extract = 0;
            }
            ben->state = DICT_KEY_MATCH;
        } else if (isdigit(px[i])) {
            ben->number *= 10;
            ben->number += px[i] - '0';
        } else {
            ben->state = ~0;
        }
        break;

    case DICT_KEY_MATCH:
        if (ben->number <= ben->keyname_length 
            && px[i] == ben->keyname[ben->keyname_offset + ben->keyname_length - ben->number]) {
            /* still good */
        } else {
            ben->is_extract = 0;
        }
        ben->number--;
        if (ben->number == 0)
            ben->state = ANYTYPE;
        break;
    default:
        //printf("smells:bittorrent:dht: inernal error\n");
        ben->state = ~0;
        i = length;
        break;
    }

    return 0;
}


enum DHT_Type {
    DHT_Unknown,
    DHT_Query,
    DHT_Response,
};
struct BitTorrentDHT {
    enum DHT_Type type;

    unsigned char id[20];

};



static inline int EQUALS(const char *str, const unsigned char *value, size_t value_length)
{
    size_t i;

    for (i=0; i<value_length; i++) {
        if (str[i] != value[i])
            return 0;
    }
    if (str[i] != '\0')
        return 0;
    return 1;
}

/****************************************************************************
 ****************************************************************************/
unsigned
smellslike_bittorrent_DHT(const unsigned char *px, unsigned length)
{
    struct BenDecode ben[1];
    struct BitTorrentDHT dht[1];
    unsigned char value[256];
    unsigned char transaction_id[32];
    unsigned transaction_id_length;
    unsigned char id[32];
    //unsigned id_length;

    unsigned x;


    if (length < 2)
        return 0;
    if (px[0] != 'd')
        return 0;
    if (!isdigit(px[1]))
        return 0;

#define KEY(x) ("\0" x "\0")

    /*
     * Transaction ID: for matching up requests with responses
     */
    bendecode_init(ben, KEY("t"), Ben_String, transaction_id, sizeof(transaction_id));
    x = bendecode(ben, px, length);
    if (!x)
        return 0;
    transaction_id_length = ben->value_length;
    if (transaction_id_length == 0)
        return 0;

    /*
     * TYPE
     */
    bendecode_init(ben, KEY("y"), Ben_String, value, sizeof(value));
    x = bendecode(ben, px, length);
    if (!x)
        return 0;
    if (ben->value_length != 1)
        return 0;
    if (value[0] == 'q')
        dht->type = DHT_Query;
    else if (value[0] == 'r')
        dht->type = DHT_Response;
    else
        return 0;

    /* Do query logic */
    if (dht->type == DHT_Query) {
        bendecode_init(ben, KEY("a\0id"), Ben_String, id, sizeof(id));
        x = bendecode(ben, px, length);
        if (!x)
            return 0;
        //id_length = ben->value_length;
        if (transaction_id_length == 0)
            return 0;

        bendecode_init(ben, KEY("q"), Ben_String, value, sizeof(value));
        x = bendecode(ben, px, length);
        if (!x)
            return 0;

        if (EQUALS("ping", value, ben->value_length)) {
            return 1;
        } else if (EQUALS("find_node", value, ben->value_length)) {
            return 1;
        } else if (EQUALS("get_peers", value, ben->value_length)) {
            return 1;
        } else if (EQUALS("announce_peer", value, ben->value_length)) {
            return 1;
        } else if (EQUALS("vote", value, ben->value_length)) {
            return 1;
        } else {
            /* unknown packet type */
            return 0;
        }
    }

    if (dht->type == DHT_Response) {
        bendecode_init(ben, KEY("r\0id"), Ben_String, id, sizeof(id));
        x = bendecode(ben, px, length);
        if (!x)
            return 0;
        //id_length = ben->value_length;
        if (transaction_id_length == 0)
            return 0;

        return 1;
    }

    return 0;
}



/****************************************************************************
 ****************************************************************************/
int
smells_selftest_bittorrent_dht(void)
{
    unsigned i;
    static const char *examples[] = {
        "d1:ad2:id20:.z..zfOI..d.IXV...UPe1:q4:ping1:t4:.c-.1:v4:UTs.1:y1:qe",

        /* ping */
        "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
        "d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re",

        /* find node */
        "d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe",
        "d1:rd2:id20:0123456789abcdefghij5:nodes9:def456...e1:t2:aa1:y1:re",
        
        /* get peers */
        "d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe",
        "d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re",
        "d1:rd2:id20:abcdefghij01234567895:nodes9:def456...5:token8:aoeusnthe1:t2:aa1:y1:re",

        /* announce peer */
        "d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe",
        "d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re",
        0
    };

#define ASSURT(x) if (!(x)  + 1

    for (i=0; examples[i]; i++) {
        unsigned x;
        
        x = smellslike_bittorrent_DHT((const unsigned char*)examples[i], strlen(examples[i]));

        if (!x) {
            printf("smells:bittorent:dht: failed\n");
            return 1; /* fail */
        }
    }
    return 0; /* success */
}