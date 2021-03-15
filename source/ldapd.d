module ldapd;



        import core.stdc.config;
        import core.stdc.stdarg: va_list;
        static import core.simd;
        static import std.conv;

        struct Int128 { long lower; long upper; }
        struct UInt128 { ulong lower; ulong upper; }

        struct __locale_data { int dummy; }



alias _Bool = bool;
struct dpp {
    static struct Opaque(int N) {
        void[N] bytes;
    }

    static bool isEmpty(T)() {
        return T.tupleof.length == 0;
    }
    static struct Move(T) {
        T* ptr;
    }


    static auto move(T)(ref T value) {
        return Move!T(&value);
    }
    mixin template EnumD(string name, T, string prefix) if(is(T == enum)) {
        private static string _memberMixinStr(string member) {
            import std.conv: text;
            import std.array: replace;
            return text(` `, member.replace(prefix, ""), ` = `, T.stringof, `.`, member, `,`);
        }
        private static string _enumMixinStr() {
            import std.array: join;
            string[] ret;
            ret ~= "enum " ~ name ~ "{";
            static foreach(member; __traits(allMembers, T)) {
                ret ~= _memberMixinStr(member);
            }
            ret ~= "}";
            return ret.join("\n");
        }
        mixin(_enumMixinStr());
    }
}

extern(C)
{
    alias size_t = c_ulong;
    int strncasecmp_l(const(char)*, const(char)*, c_ulong, __locale_struct*) @nogc nothrow;
    int strcasecmp_l(const(char)*, const(char)*, __locale_struct*) @nogc nothrow;
    int strncasecmp(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    int strcasecmp(const(char)*, const(char)*) @nogc nothrow;
    int ffsll(long) @nogc nothrow;
    int ffsl(c_long) @nogc nothrow;
    int ffs(int) @nogc nothrow;
    char* rindex(const(char)*, int) @nogc nothrow;
    char* index(const(char)*, int) @nogc nothrow;
    void bzero(void*, c_ulong) @nogc nothrow;
    void bcopy(const(void)*, void*, c_ulong) @nogc nothrow;
    int bcmp(const(void)*, const(void)*, c_ulong) @nogc nothrow;
    char* stpncpy(char*, const(char)*, c_ulong) @nogc nothrow;
    char* __stpncpy(char*, const(char)*, c_ulong) @nogc nothrow;
    char* stpcpy(char*, const(char)*) @nogc nothrow;
    char* __stpcpy(char*, const(char)*) @nogc nothrow;
    char* strsignal(int) @nogc nothrow;
    char* strsep(char**, const(char)*) @nogc nothrow;
    void explicit_bzero(void*, c_ulong) @nogc nothrow;
    char* strerror_l(int, __locale_struct*) @nogc nothrow;
    int strerror_r(int, char*, c_ulong) @nogc nothrow;
    char* strerror(int) @nogc nothrow;
    c_ulong strnlen(const(char)*, c_ulong) @nogc nothrow;
    c_ulong strlen(const(char)*) @nogc nothrow;
    char* strtok_r(char*, const(char)*, char**) @nogc nothrow;
    char* __strtok_r(char*, const(char)*, char**) @nogc nothrow;
    char* strtok(char*, const(char)*) @nogc nothrow;
    char* strstr(const(char)*, const(char)*) @nogc nothrow;
    char* strpbrk(const(char)*, const(char)*) @nogc nothrow;
    c_ulong strspn(const(char)*, const(char)*) @nogc nothrow;
    c_ulong strcspn(const(char)*, const(char)*) @nogc nothrow;
    char* strrchr(const(char)*, int) @nogc nothrow;
    char* strchr(const(char)*, int) @nogc nothrow;
    char* strndup(const(char)*, c_ulong) @nogc nothrow;
    char* strdup(const(char)*) @nogc nothrow;
    c_ulong strxfrm_l(char*, const(char)*, c_ulong, __locale_struct*) @nogc nothrow;
    int strcoll_l(const(char)*, const(char)*, __locale_struct*) @nogc nothrow;
    c_ulong strxfrm(char*, const(char)*, c_ulong) @nogc nothrow;
    int strcoll(const(char)*, const(char)*) @nogc nothrow;
    int strncmp(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    int strcmp(const(char)*, const(char)*) @nogc nothrow;
    char* strncat(char*, const(char)*, c_ulong) @nogc nothrow;
    char* strcat(char*, const(char)*) @nogc nothrow;
    char* strncpy(char*, const(char)*, c_ulong) @nogc nothrow;
    char* strcpy(char*, const(char)*) @nogc nothrow;
    void* memchr(const(void)*, int, c_ulong) @nogc nothrow;
    int memcmp(const(void)*, const(void)*, c_ulong) @nogc nothrow;
    void* memset(void*, int, c_ulong) @nogc nothrow;
    void* memccpy(void*, const(void)*, int, c_ulong) @nogc nothrow;
    void* memmove(void*, const(void)*, c_ulong) @nogc nothrow;
    void* memcpy(void*, const(void)*, c_ulong) @nogc nothrow;
    int ldap_parse_ntlm_bind_result(ldap*, ldapmsg*, berval*) @nogc nothrow;
    int ldap_ntlm_bind(ldap*, const(char)*, c_ulong, berval*, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_parse_deref_control(ldap*, ldapcontrol**, LDAPDerefRes**) @nogc nothrow;
    int ldap_parse_derefresponse_control(ldap*, ldapcontrol*, LDAPDerefRes**) @nogc nothrow;
    void ldap_derefresponse_free(LDAPDerefRes*) @nogc nothrow;
    int ldap_create_deref_control(ldap*, LDAPDerefSpec*, int, ldapcontrol**) @nogc nothrow;
    int ldap_create_deref_control_value(ldap*, LDAPDerefSpec*, berval*) @nogc nothrow;
    struct LDAPDerefRes
    {
        char* derefAttr;
        berval derefVal;
        LDAPDerefVal* attrVals;
        LDAPDerefRes* next;
    }
    struct LDAPDerefVal
    {
        char* type;
        berval* vals;
        LDAPDerefVal* next;
    }
    struct LDAPDerefSpec
    {
        char* derefAttr;
        char** attributes;
    }
    int ldap_create_assertion_control(ldap*, char*, int, ldapcontrol**) @nogc nothrow;
    int ldap_create_assertion_control_value(ldap*, char*, berval*) @nogc nothrow;
    int ldap_parse_session_tracking_control(ldap*, ldapcontrol*, berval*, berval*, berval*, berval*) @nogc nothrow;
    int ldap_create_session_tracking_control(ldap*, char*, char*, char*, berval*, ldapcontrol**) @nogc nothrow;
    int ldap_create_session_tracking_value(ldap*, char*, char*, char*, berval*, berval*) @nogc nothrow;
    int ldap_sync_poll(ldap_sync_t*) @nogc nothrow;
    int ldap_sync_init_refresh_and_persist(ldap_sync_t*) @nogc nothrow;
    int ldap_sync_init_refresh_only(ldap_sync_t*) @nogc nothrow;
    int ldap_sync_init(ldap_sync_t*, int) @nogc nothrow;
    struct __locale_struct
    {
        __locale_data*[13] __locales;
        const(ushort)* __ctype_b;
        const(int)* __ctype_tolower;
        const(int)* __ctype_toupper;
        const(char)*[13] __names;
    }
    alias __locale_t = __locale_struct*;
    alias locale_t = __locale_struct*;
    void ldap_sync_destroy(ldap_sync_t*, int) @nogc nothrow;
    ldap_sync_t* ldap_sync_initialize(ldap_sync_t*) @nogc nothrow;
    int ldap_refresh_s(ldap*, berval*, int, int*, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_refresh(ldap*, berval*, int, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_parse_refresh(ldap*, ldapmsg*, int*) @nogc nothrow;
    const(char)* ldap_passwordpolicy_err2txt(passpolicyerror_enum) @nogc nothrow;
    int ldap_parse_passwordpolicy_control(ldap*, ldapcontrol*, int*, int*, passpolicyerror_enum*) @nogc nothrow;
    int ldap_create_passwordpolicy_control(ldap*, ldapcontrol**) @nogc nothrow;
    enum passpolicyerror_enum
    {
        PP_passwordExpired = 0,
        PP_accountLocked = 1,
        PP_changeAfterReset = 2,
        PP_passwordModNotAllowed = 3,
        PP_mustSupplyOldPassword = 4,
        PP_insufficientPasswordQuality = 5,
        PP_passwordTooShort = 6,
        PP_passwordTooYoung = 7,
        PP_passwordInHistory = 8,
        PP_noError = 65535,
    }
    enum PP_passwordExpired = passpolicyerror_enum.PP_passwordExpired;
    enum PP_accountLocked = passpolicyerror_enum.PP_accountLocked;
    enum PP_changeAfterReset = passpolicyerror_enum.PP_changeAfterReset;
    enum PP_passwordModNotAllowed = passpolicyerror_enum.PP_passwordModNotAllowed;
    enum PP_mustSupplyOldPassword = passpolicyerror_enum.PP_mustSupplyOldPassword;
    enum PP_insufficientPasswordQuality = passpolicyerror_enum.PP_insufficientPasswordQuality;
    enum PP_passwordTooShort = passpolicyerror_enum.PP_passwordTooShort;
    enum PP_passwordTooYoung = passpolicyerror_enum.PP_passwordTooYoung;
    enum PP_passwordInHistory = passpolicyerror_enum.PP_passwordInHistory;
    enum PP_noError = passpolicyerror_enum.PP_noError;
    alias LDAPPasswordPolicyError = passpolicyerror_enum;
    int ldap_passwd_s(ldap*, berval*, berval*, berval*, berval*, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_passwd(ldap*, berval*, berval*, berval*, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_parse_passwd(ldap*, ldapmsg*, berval*) @nogc nothrow;
    int ldap_whoami_s(ldap*, berval**, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_whoami(ldap*, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_parse_whoami(ldap*, ldapmsg*, berval**) @nogc nothrow;
    int ldap_parse_vlvresponse_control(ldap*, ldapcontrol*, int*, int*, berval**, int*) @nogc nothrow;
    int ldap_create_vlv_control(ldap*, ldapvlvinfo*, ldapcontrol**) @nogc nothrow;
    int ldap_create_vlv_control_value(ldap*, ldapvlvinfo*, berval*) @nogc nothrow;
    struct ldapvlvinfo
    {
        int ldvlv_version;
        int ldvlv_before_count;
        int ldvlv_after_count;
        int ldvlv_offset;
        int ldvlv_count;
        berval* ldvlv_attrvalue;
        berval* ldvlv_context;
        void* ldvlv_extradata;
    }
    alias LDAPVLVInfo = ldapvlvinfo;
    int ldap_parse_sortresponse_control(ldap*, ldapcontrol*, int*, char**) @nogc nothrow;
    int ldap_create_sort_control(ldap*, ldapsortkey**, int, ldapcontrol**) @nogc nothrow;
    int ldap_create_sort_control_value(ldap*, ldapsortkey**, berval*) @nogc nothrow;
    void ldap_free_sort_keylist(ldapsortkey**) @nogc nothrow;
    int ldap_create_sort_keylist(ldapsortkey***, char*) @nogc nothrow;
    struct ldapsortkey
    {
        char* attributeType;
        char* orderingRule;
        int reverseOrder;
    }
    alias LDAPSortKey = ldapsortkey;
    int ldap_parse_pageresponse_control(ldap*, ldapcontrol*, int*, berval*) @nogc nothrow;
    int ldap_create_page_control(ldap*, int, berval*, int, ldapcontrol**) @nogc nothrow;
    int ldap_create_page_control_value(ldap*, int, berval*, berval*) @nogc nothrow;
    alias BER_ERRNO_FN = int* function();
    alias BER_LOG_PRINT_FN = void function(const(char)*);
    alias BER_MEMALLOC_FN = void* function(c_ulong, void*);
    alias BER_MEMCALLOC_FN = void* function(c_ulong, c_ulong, void*);
    alias BER_MEMREALLOC_FN = void* function(void*, c_ulong, void*);
    alias BER_MEMFREE_FN = void function(void*, void*);
    alias BerMemoryFunctions = lber_memory_fns;
    struct lber_memory_fns
    {
        void* function(c_ulong, void*) bmf_malloc;
        void* function(c_ulong, c_ulong, void*) bmf_calloc;
        void* function(void*, c_ulong, void*) bmf_realloc;
        void function(void*, void*) bmf_free;
    }
    int ldap_turn_s(ldap*, int, const(char)*, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_turn(ldap*, int, const(char)*, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_cancel_s(ldap*, int, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_cancel(ldap*, int, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    void ldap_free_urldesc(ldap_url_desc*) @nogc nothrow;
    char* ldap_url_desc2str(ldap_url_desc*) @nogc nothrow;
    extern __gshared char ber_pvt_opt_on;
    int ldap_url_parse(const(char)*, ldap_url_desc**) @nogc nothrow;
    alias BerElement = berelement;
    struct berelement;
    alias Sockbuf = sockbuf;
    struct sockbuf;
    alias Sockbuf_IO = sockbuf_io;
    struct sockbuf_io
    {
        int function(sockbuf_io_desc*, void*) sbi_setup;
        int function(sockbuf_io_desc*) sbi_remove;
        int function(sockbuf_io_desc*, int, void*) sbi_ctrl;
        c_long function(sockbuf_io_desc*, void*, c_ulong) sbi_read;
        c_long function(sockbuf_io_desc*, void*, c_ulong) sbi_write;
        int function(sockbuf_io_desc*) sbi_close;
    }
    alias Sockbuf_IO_Desc = sockbuf_io_desc;
    struct sockbuf_io_desc
    {
        int sbiod_level;
        sockbuf* sbiod_sb;
        sockbuf_io* sbiod_io;
        void* sbiod_pvt;
        sockbuf_io_desc* sbiod_next;
    }
    int ldap_is_ldapi_url(const(char)*) @nogc nothrow;
    alias BerValue = berval;
    struct berval
    {
        c_ulong bv_len;
        char* bv_val;
    }
    alias BerVarray = berval*;
    void ber_error_print(const(char)*) @nogc nothrow;
    void ber_bprint(const(char)*, c_ulong) @nogc nothrow;
    void ber_dump(berelement*, int) @nogc nothrow;
    alias BERDecodeCallback = int function(berelement*, void*, int);
    c_ulong ber_get_tag(berelement*) @nogc nothrow;
    c_ulong ber_skip_tag(berelement*, c_ulong*) @nogc nothrow;
    c_ulong ber_peek_tag(berelement*, c_ulong*) @nogc nothrow;
    c_ulong ber_skip_element(berelement*, berval*) @nogc nothrow;
    c_ulong ber_peek_element(const(berelement)*, berval*) @nogc nothrow;
    c_ulong ber_get_int(berelement*, int*) @nogc nothrow;
    c_ulong ber_get_enum(berelement*, int*) @nogc nothrow;
    c_ulong ber_get_stringb(berelement*, char*, c_ulong*) @nogc nothrow;
    c_ulong ber_get_stringbv(berelement*, berval*, int) @nogc nothrow;
    c_ulong ber_get_stringa(berelement*, char**) @nogc nothrow;
    c_ulong ber_get_stringal(berelement*, berval**) @nogc nothrow;
    c_ulong ber_get_bitstringa(berelement*, char**, c_ulong*) @nogc nothrow;
    c_ulong ber_get_null(berelement*) @nogc nothrow;
    c_ulong ber_get_boolean(berelement*, int*) @nogc nothrow;
    c_ulong ber_first_element(berelement*, c_ulong*, char**) @nogc nothrow;
    c_ulong ber_next_element(berelement*, c_ulong*, const(char)*) @nogc nothrow;
    c_ulong ber_scanf(berelement*, const(char)*, ...) @nogc nothrow;
    int ber_decode_oid(berval*, berval*) @nogc nothrow;
    int ber_encode_oid(berval*, berval*) @nogc nothrow;
    alias BEREncodeCallback = int function(berelement*, void*);
    int ber_put_enum(berelement*, int, c_ulong) @nogc nothrow;
    int ber_put_int(berelement*, int, c_ulong) @nogc nothrow;
    int ber_put_ostring(berelement*, const(char)*, c_ulong, c_ulong) @nogc nothrow;
    int ber_put_berval(berelement*, berval*, c_ulong) @nogc nothrow;
    int ber_put_string(berelement*, const(char)*, c_ulong) @nogc nothrow;
    int ber_put_bitstring(berelement*, const(char)*, c_ulong, c_ulong) @nogc nothrow;
    int ber_put_null(berelement*, c_ulong) @nogc nothrow;
    int ber_put_boolean(berelement*, int, c_ulong) @nogc nothrow;
    int ber_start_seq(berelement*, c_ulong) @nogc nothrow;
    int ber_start_set(berelement*, c_ulong) @nogc nothrow;
    int ber_put_seq(berelement*) @nogc nothrow;
    int ber_put_set(berelement*) @nogc nothrow;
    int ber_printf(berelement*, const(char)*, ...) @nogc nothrow;
    c_long ber_skip_data(berelement*, c_ulong) @nogc nothrow;
    c_long ber_read(berelement*, char*, c_ulong) @nogc nothrow;
    c_long ber_write(berelement*, const(char)*, c_ulong, int) @nogc nothrow;
    void ber_free(berelement*, int) @nogc nothrow;
    void ber_free_buf(berelement*) @nogc nothrow;
    int ber_flush2(sockbuf*, berelement*, int) @nogc nothrow;
    int ldap_is_ldaps_url(const(char)*) @nogc nothrow;
    int ber_flush(sockbuf*, berelement*, int) @nogc nothrow;
    berelement* ber_alloc() @nogc nothrow;
    berelement* der_alloc() @nogc nothrow;
    berelement* ber_alloc_t(int) @nogc nothrow;
    berelement* ber_dup(berelement*) @nogc nothrow;
    c_ulong ber_get_next(sockbuf*, c_ulong*, berelement*) @nogc nothrow;
    void ber_init2(berelement*, berval*, int) @nogc nothrow;
    void ber_init_w_nullc(berelement*, int) @nogc nothrow;
    void ber_reset(berelement*, int) @nogc nothrow;
    berelement* ber_init(berval*) @nogc nothrow;
    int ber_flatten(berelement*, berval**) @nogc nothrow;
    int ber_flatten2(berelement*, berval*, int) @nogc nothrow;
    int ber_remaining(berelement*) @nogc nothrow;
    int ber_get_option(void*, int, void*) @nogc nothrow;
    int ber_set_option(void*, int, const(void)*) @nogc nothrow;
    sockbuf* ber_sockbuf_alloc() @nogc nothrow;
    void ber_sockbuf_free(sockbuf*) @nogc nothrow;
    int ber_sockbuf_add_io(sockbuf*, sockbuf_io*, int, void*) @nogc nothrow;
    int ber_sockbuf_remove_io(sockbuf*, sockbuf_io*, int) @nogc nothrow;
    int ber_sockbuf_ctrl(sockbuf*, int, void*) @nogc nothrow;
    extern __gshared sockbuf_io ber_sockbuf_io_tcp;
    extern __gshared sockbuf_io ber_sockbuf_io_readahead;
    extern __gshared sockbuf_io ber_sockbuf_io_fd;
    extern __gshared sockbuf_io ber_sockbuf_io_debug;
    extern __gshared sockbuf_io ber_sockbuf_io_udp;
    void* ber_memalloc(c_ulong) @nogc nothrow;
    void* ber_memrealloc(void*, c_ulong) @nogc nothrow;
    void* ber_memcalloc(c_ulong, c_ulong) @nogc nothrow;
    void ber_memfree(void*) @nogc nothrow;
    void ber_memvfree(void**) @nogc nothrow;
    void ber_bvfree(berval*) @nogc nothrow;
    void ber_bvecfree(berval**) @nogc nothrow;
    int ber_bvecadd(berval***, berval*) @nogc nothrow;
    berval* ber_dupbv(berval*, berval*) @nogc nothrow;
    berval* ber_bvdup(berval*) @nogc nothrow;
    berval* ber_mem2bv(const(char)*, c_ulong, int, berval*) @nogc nothrow;
    berval* ber_str2bv(const(char)*, c_ulong, int, berval*) @nogc nothrow;
    int ldap_is_ldap_url(const(char)*) @nogc nothrow;
    char* ber_strdup(const(char)*) @nogc nothrow;
    c_ulong ber_strnlen(const(char)*, c_ulong) @nogc nothrow;
    char* ber_strndup(const(char)*, c_ulong) @nogc nothrow;
    berval* ber_bvreplace(berval*, const(berval)*) @nogc nothrow;
    void ber_bvarray_free(berval*) @nogc nothrow;
    int ber_bvarray_add(berval**, berval*) @nogc nothrow;
    int* ber_errno_addr() @nogc nothrow;
    void ldap_mods_free(ldapmod**, int) @nogc nothrow;
    char* ldap_strdup(const(char)*) @nogc nothrow;
    void ldap_memvfree(void**) @nogc nothrow;
    alias ber_int_t = int;
    alias ber_sint_t = int;
    alias ber_uint_t = uint;
    alias ber_tag_t = c_ulong;
    alias ber_socket_t = int;
    alias ber_len_t = c_ulong;
    alias ber_slen_t = c_long;
    void ldap_memfree(void*) @nogc nothrow;
    void* ldap_memcalloc(c_ulong, c_ulong) @nogc nothrow;
    void* ldap_memrealloc(void*, c_ulong) @nogc nothrow;
    void* ldap_memalloc(c_ulong) @nogc nothrow;
    int ldap_put_vrFilter(berelement*, const(char)*) @nogc nothrow;
    int ldap_destroy(ldap*) @nogc nothrow;
    int ldap_unbind_ext_s(ldap*, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_unbind_ext(ldap*, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_search_ext_s(ldap*, const(char)*, int, const(char)*, char**, int, ldapcontrol**, ldapcontrol**, timeval*, int, ldapmsg**) @nogc nothrow;
    int ldap_search_ext(ldap*, const(char)*, int, const(char)*, char**, int, ldapcontrol**, ldapcontrol**, timeval*, int, int*) @nogc nothrow;
    int ldap_bv2escaped_filter_value(berval*, berval*) @nogc nothrow;
    int ldap_msgdelete(ldap*, int) @nogc nothrow;
    int ldap_msgfree(ldapmsg*) @nogc nothrow;
    int ldap_msgid(ldapmsg*) @nogc nothrow;
    int ldap_msgtype(ldapmsg*) @nogc nothrow;
    int ldap_result(ldap*, int, int, timeval*, ldapmsg**) @nogc nothrow;
    void ldap_value_free_len(berval**) @nogc nothrow;
    int ldap_count_values_len(berval**) @nogc nothrow;
    berval** ldap_get_values_len(ldap*, ldapmsg*, const(char)*) @nogc nothrow;
    char* ldap_next_attribute(ldap*, ldapmsg*, berelement*) @nogc nothrow;
    char* ldap_first_attribute(ldap*, ldapmsg*, berelement**) @nogc nothrow;
    int ldap_get_attribute_ber(ldap*, ldapmsg*, berelement*, berval*, berval**) @nogc nothrow;
    int ldap_get_dn_ber(ldap*, ldapmsg*, berelement**, berval*) @nogc nothrow;
    char* ldap_dn2ad_canonical(const(char)*) @nogc nothrow;
    char* ldap_dcedn2dn(const(char)*) @nogc nothrow;
    char* ldap_dn2dcedn(const(char)*) @nogc nothrow;
    int ldap_X509dn2bv(void*, berval*, int function(ldap_ava***, uint, void*), uint) @nogc nothrow;
    alias LDAPDN_rewrite_func = int function(ldap_ava***, uint, void*);
    char** ldap_explode_rdn(const(char)*, int) @nogc nothrow;
    char** ldap_explode_dn(const(char)*, int) @nogc nothrow;
    char* ldap_dn2ufn(const(char)*) @nogc nothrow;
    int ldap_dn_normalize(const(char)*, uint, char**, uint) @nogc nothrow;
    int ldap_rdn2str(ldap_ava**, char**, uint) @nogc nothrow;
    alias LDAPAPIInfo = ldapapiinfo;
    struct ldapapiinfo
    {
        int ldapai_info_version;
        int ldapai_api_version;
        int ldapai_protocol_version;
        char** ldapai_extensions;
        char* ldapai_vendor_name;
        int ldapai_vendor_version;
    }
    alias LDAPAPIFeatureInfo = ldap_apifeature_info;
    struct ldap_apifeature_info
    {
        int ldapaif_info_version;
        char* ldapaif_name;
        int ldapaif_version;
    }
    alias LDAPControl = ldapcontrol;
    struct ldapcontrol
    {
        char* ldctl_oid;
        berval ldctl_value;
        char ldctl_iscritical;
    }
    int ldap_rdn2bv(ldap_ava**, berval*, uint) @nogc nothrow;
    int ldap_str2rdn(const(char)*, ldap_ava***, char**, uint) @nogc nothrow;
    int ldap_bv2rdn(berval*, ldap_ava***, char**, uint) @nogc nothrow;
    int ldap_dn2str(ldap_ava***, char**, uint) @nogc nothrow;
    int ldap_dn2bv(ldap_ava***, berval*, uint) @nogc nothrow;
    int ldap_str2dn(const(char)*, ldap_ava****, uint) @nogc nothrow;
    int ldap_bv2dn(berval*, ldap_ava****, uint) @nogc nothrow;
    void ldap_dnfree(ldap_ava***) @nogc nothrow;
    void ldap_rdnfree(ldap_ava**) @nogc nothrow;
    alias LDAPDN = ldap_ava***;
    alias LDAPRDN = ldap_ava**;
    struct ldap_ava
    {
        berval la_attr;
        berval la_value;
        uint la_flags;
        void* la_private;
    }
    alias LDAPAVA = ldap_ava;
    char* ldap_get_dn(ldap*, ldapmsg*) @nogc nothrow;
    void ldap_add_result_entry(ldapmsg**, ldapmsg*) @nogc nothrow;
    ldapmsg* ldap_delete_result_entry(ldapmsg**, ldapmsg*) @nogc nothrow;
    int ldap_get_entry_controls(ldap*, ldapmsg*, ldapcontrol***) @nogc nothrow;
    int ldap_count_entries(ldap*, ldapmsg*) @nogc nothrow;
    ldapmsg* ldap_next_entry(ldap*, ldapmsg*) @nogc nothrow;
    ldapmsg* ldap_first_entry(ldap*, ldapmsg*) @nogc nothrow;
    int ldap_parse_reference(ldap*, ldapmsg*, char***, ldapcontrol***, int) @nogc nothrow;
    int ldap_count_references(ldap*, ldapmsg*) @nogc nothrow;
    ldapmsg* ldap_next_reference(ldap*, ldapmsg*) @nogc nothrow;
    ldapmsg* ldap_first_reference(ldap*, ldapmsg*) @nogc nothrow;
    int ldap_count_messages(ldap*, ldapmsg*) @nogc nothrow;
    ldapmsg* ldap_next_message(ldap*, ldapmsg*) @nogc nothrow;
    ldapmsg* ldap_first_message(ldap*, ldapmsg*) @nogc nothrow;
    int ldap_start_tls_s(ldap*, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_install_tls(ldap*) @nogc nothrow;
    int ldap_start_tls(ldap*, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_tls_inplace(ldap*) @nogc nothrow;
    ldap* ldap_dup(ldap*) @nogc nothrow;
    int ldap_initialize(ldap**, const(char)*) @nogc nothrow;
    int ldap_create(ldap**) @nogc nothrow;
    int ldap_rename_s(ldap*, const(char)*, const(char)*, const(char)*, int, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_rename(ldap*, const(char)*, const(char)*, const(char)*, int, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_modify_ext_s(ldap*, const(char)*, ldapmod**, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_modify_ext(ldap*, const(char)*, ldapmod**, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_gssapi_bind_s(ldap*, const(char)*, const(char)*) @nogc nothrow;
    int ldap_gssapi_bind(ldap*, const(char)*, const(char)*) @nogc nothrow;
    char* ldap_err2string(int) @nogc nothrow;
    int ldap_parse_result(ldap*, ldapmsg*, int*, char**, char**, char***, ldapcontrol***, int) @nogc nothrow;
    int ldap_delete_ext_s(ldap*, const(char)*, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_delete_ext(ldap*, const(char)*, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_compare_ext_s(ldap*, const(char)*, const(char)*, berval*, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_compare_ext(ldap*, const(char)*, const(char)*, berval*, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_parse_sasl_bind_result(ldap*, ldapmsg*, berval**, int) @nogc nothrow;
    int ldap_sasl_bind_s(ldap*, const(char)*, const(char)*, berval*, ldapcontrol**, ldapcontrol**, berval**) @nogc nothrow;
    int ldap_sasl_interactive_bind_s(ldap*, const(char)*, const(char)*, ldapcontrol**, ldapcontrol**, uint, int function(ldap*, uint, void*, void*), void*) @nogc nothrow;
    int ldap_sasl_interactive_bind(ldap*, const(char)*, const(char)*, ldapcontrol**, ldapcontrol**, uint, int function(ldap*, uint, void*, void*), void*, ldapmsg*, const(char)**, int*) @nogc nothrow;
    alias LDAP_SASL_INTERACT_PROC = int function(ldap*, uint, void*, void*);
    int ldap_sasl_bind(ldap*, const(char)*, const(char)*, berval*, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_add_ext_s(ldap*, const(char)*, ldapmod**, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_add_ext(ldap*, const(char)*, ldapmod**, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_abandon_ext(ldap*, int, ldapcontrol**, ldapcontrol**) @nogc nothrow;
    int ldap_parse_intermediate(ldap*, ldapmsg*, char**, berval**, ldapcontrol***, int) @nogc nothrow;
    int ldap_parse_extended_result(ldap*, ldapmsg*, char**, berval**, int) @nogc nothrow;
    int ldap_extended_operation_s(ldap*, const(char)*, berval*, ldapcontrol**, ldapcontrol**, char**, berval**) @nogc nothrow;
    int ldap_extended_operation(ldap*, const(char)*, berval*, ldapcontrol**, ldapcontrol**, int*) @nogc nothrow;
    int ldap_domain2hostlist(const(char)*, char**) @nogc nothrow;
    int ldap_dn2domain(const(char)*, char**) @nogc nothrow;
    int ldap_domain2dn(const(char)*, char**) @nogc nothrow;
    ldapcontrol* ldap_control_dup(const(ldapcontrol)*) @nogc nothrow;
    ldapcontrol** ldap_controls_dup(ldapcontrol**) @nogc nothrow;
    void ldap_controls_free(ldapcontrol**) @nogc nothrow;
    void ldap_control_free(ldapcontrol*) @nogc nothrow;
    ldapcontrol* ldap_control_find(const(char)*, ldapcontrol**, ldapcontrol***) @nogc nothrow;
    int ldap_control_create(const(char)*, int, berval*, int, ldapcontrol**) @nogc nothrow;
    int ldap_set_urllist_proc(ldap*, int function(ldap*, ldap_url_desc**, ldap_url_desc**, void*), void*) @nogc nothrow;
    alias LDAP_URLLIST_PROC = int function(ldap*, ldap_url_desc**, ldap_url_desc**, void*);
    int ldap_set_nextref_proc(ldap*, int function(ldap*, char***, int*, void*), void*) @nogc nothrow;
    alias LDAP_NEXTREF_PROC = int function(ldap*, char***, int*, void*);
    int ldap_set_rebind_proc(ldap*, int function(ldap*, const(char)*, c_ulong, int, void*), void*) @nogc nothrow;
    alias LDAP_REBIND_PROC = int function(ldap*, const(char)*, c_ulong, int, void*);
    int ldap_set_option(ldap*, int, const(void)*) @nogc nothrow;
    int ldap_get_option(ldap*, int, void*) @nogc nothrow;

    struct timeval {
		import core.stdc.time;
		time_t tv_sec;
		long tv_usec;
	}

    alias ldap_conn_del_f = void function(ldap*, sockbuf*, ldap_conncb*);
    alias ldap_conn_add_f = int function(ldap*, sockbuf*, ldap_url_desc*, sockaddr*, ldap_conncb*);
    struct sockaddr;
    struct ldap_conncb
    {
        int function(ldap*, sockbuf*, ldap_url_desc*, sockaddr*, ldap_conncb*) lc_add;
        void function(ldap*, sockbuf*, ldap_conncb*) lc_del;
        void* lc_arg;
    }
    alias ldap_sync_search_result_f = int function(ldap_sync_t*, ldapmsg*, int);
    alias ldap_sync_intermediate_f = int function(ldap_sync_t*, ldapmsg*, berval*, ldap_sync_refresh_t);
    alias ldap_sync_search_reference_f = int function(ldap_sync_t*, ldapmsg*);
    alias ldap_sync_search_entry_f = int function(ldap_sync_t*, ldapmsg*, berval*, ldap_sync_refresh_t);
    enum _Anonymous_0
    {
        LDAP_SYNC_CAPI_NONE = -1,
        LDAP_SYNC_CAPI_PHASE_FLAG = 16,
        LDAP_SYNC_CAPI_IDSET_FLAG = 32,
        LDAP_SYNC_CAPI_DONE_FLAG = 64,
        LDAP_SYNC_CAPI_PRESENT = 0,
        LDAP_SYNC_CAPI_ADD = 1,
        LDAP_SYNC_CAPI_MODIFY = 2,
        LDAP_SYNC_CAPI_DELETE = 3,
        LDAP_SYNC_CAPI_PRESENTS = 16,
        LDAP_SYNC_CAPI_DELETES = 19,
        LDAP_SYNC_CAPI_PRESENTS_IDSET = 48,
        LDAP_SYNC_CAPI_DELETES_IDSET = 51,
        LDAP_SYNC_CAPI_DONE = 80,
    }
    enum LDAP_SYNC_CAPI_NONE = _Anonymous_0.LDAP_SYNC_CAPI_NONE;
    enum LDAP_SYNC_CAPI_PHASE_FLAG = _Anonymous_0.LDAP_SYNC_CAPI_PHASE_FLAG;
    enum LDAP_SYNC_CAPI_IDSET_FLAG = _Anonymous_0.LDAP_SYNC_CAPI_IDSET_FLAG;
    enum LDAP_SYNC_CAPI_DONE_FLAG = _Anonymous_0.LDAP_SYNC_CAPI_DONE_FLAG;
    enum LDAP_SYNC_CAPI_PRESENT = _Anonymous_0.LDAP_SYNC_CAPI_PRESENT;
    enum LDAP_SYNC_CAPI_ADD = _Anonymous_0.LDAP_SYNC_CAPI_ADD;
    enum LDAP_SYNC_CAPI_MODIFY = _Anonymous_0.LDAP_SYNC_CAPI_MODIFY;
    enum LDAP_SYNC_CAPI_DELETE = _Anonymous_0.LDAP_SYNC_CAPI_DELETE;
    enum LDAP_SYNC_CAPI_PRESENTS = _Anonymous_0.LDAP_SYNC_CAPI_PRESENTS;
    enum LDAP_SYNC_CAPI_DELETES = _Anonymous_0.LDAP_SYNC_CAPI_DELETES;
    enum LDAP_SYNC_CAPI_PRESENTS_IDSET = _Anonymous_0.LDAP_SYNC_CAPI_PRESENTS_IDSET;
    enum LDAP_SYNC_CAPI_DELETES_IDSET = _Anonymous_0.LDAP_SYNC_CAPI_DELETES_IDSET;
    enum LDAP_SYNC_CAPI_DONE = _Anonymous_0.LDAP_SYNC_CAPI_DONE;
    alias ldap_sync_refresh_t = _Anonymous_0;
    struct ldap_sync_t
    {
        char* ls_base;
        int ls_scope;
        char* ls_filter;
        char** ls_attrs;
        int ls_timelimit;
        int ls_sizelimit;
        int ls_timeout;
        int function(ldap_sync_t*, ldapmsg*, berval*, ldap_sync_refresh_t) ls_search_entry;
        int function(ldap_sync_t*, ldapmsg*) ls_search_reference;
        int function(ldap_sync_t*, ldapmsg*, berval*, ldap_sync_refresh_t) ls_intermediate;
        int function(ldap_sync_t*, ldapmsg*, int) ls_search_result;
        void* ls_private;
        ldap* ls_ld;
        int ls_msgid;
        int ls_reloadHint;
        berval ls_cookie;
        ldap_sync_refresh_t ls_refreshPhase;
    }
    struct ldap_url_desc
    {
        ldap_url_desc* lud_next;
        char* lud_scheme;
        char* lud_host;
        int lud_port;
        char* lud_dn;
        char** lud_attrs;
        int lud_scope;
        char* lud_filter;
        char** lud_exts;
        int lud_crit_exts;
    }
    alias LDAPURLDesc = ldap_url_desc;
    alias LDAPMessage = ldapmsg;
    struct ldapmsg;
    alias LDAPMod = ldapmod;
    struct ldapmod
    {
        int mod_op;
        char* mod_type;
        union mod_vals_u
        {
            char** modv_strvals;
            berval** modv_bvals;
        }
        ldapmod.mod_vals_u mod_vals;
    }
    struct ldap;
    alias LDAP = ldap;



    static if(!is(typeof(LDAP_MOD_DELETE))) {
        private enum enumMixinStr_LDAP_MOD_DELETE = `enum LDAP_MOD_DELETE = ( 0x0001 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MOD_DELETE); }))) {
            mixin(enumMixinStr_LDAP_MOD_DELETE);
        }
    }




    static if(!is(typeof(LDAP_MOD_REPLACE))) {
        private enum enumMixinStr_LDAP_MOD_REPLACE = `enum LDAP_MOD_REPLACE = ( 0x0002 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MOD_REPLACE); }))) {
            mixin(enumMixinStr_LDAP_MOD_REPLACE);
        }
    }




    static if(!is(typeof(LDAP_MOD_INCREMENT))) {
        private enum enumMixinStr_LDAP_MOD_INCREMENT = `enum LDAP_MOD_INCREMENT = ( 0x0003 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MOD_INCREMENT); }))) {
            mixin(enumMixinStr_LDAP_MOD_INCREMENT);
        }
    }




    static if(!is(typeof(LDAP_MOD_BVALUES))) {
        private enum enumMixinStr_LDAP_MOD_BVALUES = `enum LDAP_MOD_BVALUES = ( 0x0080 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MOD_BVALUES); }))) {
            mixin(enumMixinStr_LDAP_MOD_BVALUES);
        }
    }




    static if(!is(typeof(mod_values))) {
        private enum enumMixinStr_mod_values = `enum mod_values = mod_vals . modv_strvals;`;
        static if(is(typeof({ mixin(enumMixinStr_mod_values); }))) {
            mixin(enumMixinStr_mod_values);
        }
    }




    static if(!is(typeof(mod_bvalues))) {
        private enum enumMixinStr_mod_bvalues = `enum mod_bvalues = mod_vals . modv_bvals;`;
        static if(is(typeof({ mixin(enumMixinStr_mod_bvalues); }))) {
            mixin(enumMixinStr_mod_bvalues);
        }
    }




    static if(!is(typeof(LDAP_MOD_ADD))) {
        private enum enumMixinStr_LDAP_MOD_ADD = `enum LDAP_MOD_ADD = ( 0x0000 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MOD_ADD); }))) {
            mixin(enumMixinStr_LDAP_MOD_ADD);
        }
    }




    static if(!is(typeof(LDAP_MOD_OP))) {
        private enum enumMixinStr_LDAP_MOD_OP = `enum LDAP_MOD_OP = ( 0x0007 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MOD_OP); }))) {
            mixin(enumMixinStr_LDAP_MOD_OP);
        }
    }




    static if(!is(typeof(LDAP_DEREF_NEVER))) {
        private enum enumMixinStr_LDAP_DEREF_NEVER = `enum LDAP_DEREF_NEVER = 0x00;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DEREF_NEVER); }))) {
            mixin(enumMixinStr_LDAP_DEREF_NEVER);
        }
    }




    static if(!is(typeof(LDAP_DEREF_SEARCHING))) {
        private enum enumMixinStr_LDAP_DEREF_SEARCHING = `enum LDAP_DEREF_SEARCHING = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DEREF_SEARCHING); }))) {
            mixin(enumMixinStr_LDAP_DEREF_SEARCHING);
        }
    }




    static if(!is(typeof(LDAP_DEREF_FINDING))) {
        private enum enumMixinStr_LDAP_DEREF_FINDING = `enum LDAP_DEREF_FINDING = 0x02;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DEREF_FINDING); }))) {
            mixin(enumMixinStr_LDAP_DEREF_FINDING);
        }
    }




    static if(!is(typeof(LDAP_DEREF_ALWAYS))) {
        private enum enumMixinStr_LDAP_DEREF_ALWAYS = `enum LDAP_DEREF_ALWAYS = 0x03;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DEREF_ALWAYS); }))) {
            mixin(enumMixinStr_LDAP_DEREF_ALWAYS);
        }
    }




    static if(!is(typeof(LDAP_NO_LIMIT))) {
        private enum enumMixinStr_LDAP_NO_LIMIT = `enum LDAP_NO_LIMIT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NO_LIMIT); }))) {
            mixin(enumMixinStr_LDAP_NO_LIMIT);
        }
    }




    static if(!is(typeof(LDAP_MSG_ONE))) {
        private enum enumMixinStr_LDAP_MSG_ONE = `enum LDAP_MSG_ONE = 0x00;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MSG_ONE); }))) {
            mixin(enumMixinStr_LDAP_MSG_ONE);
        }
    }




    static if(!is(typeof(LDAP_MSG_ALL))) {
        private enum enumMixinStr_LDAP_MSG_ALL = `enum LDAP_MSG_ALL = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MSG_ALL); }))) {
            mixin(enumMixinStr_LDAP_MSG_ALL);
        }
    }




    static if(!is(typeof(LDAP_MSG_RECEIVED))) {
        private enum enumMixinStr_LDAP_MSG_RECEIVED = `enum LDAP_MSG_RECEIVED = 0x02;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MSG_RECEIVED); }))) {
            mixin(enumMixinStr_LDAP_MSG_RECEIVED);
        }
    }




    static if(!is(typeof(LDAP_X_CONNECTING))) {
        private enum enumMixinStr_LDAP_X_CONNECTING = `enum LDAP_X_CONNECTING = ( - 18 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_X_CONNECTING); }))) {
            mixin(enumMixinStr_LDAP_X_CONNECTING);
        }
    }




    static if(!is(typeof(LDAP_REFERRAL_LIMIT_EXCEEDED))) {
        private enum enumMixinStr_LDAP_REFERRAL_LIMIT_EXCEEDED = `enum LDAP_REFERRAL_LIMIT_EXCEEDED = ( - 17 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REFERRAL_LIMIT_EXCEEDED); }))) {
            mixin(enumMixinStr_LDAP_REFERRAL_LIMIT_EXCEEDED);
        }
    }




    static if(!is(typeof(LDAP_URL_SUCCESS))) {
        private enum enumMixinStr_LDAP_URL_SUCCESS = `enum LDAP_URL_SUCCESS = 0x00;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_SUCCESS); }))) {
            mixin(enumMixinStr_LDAP_URL_SUCCESS);
        }
    }




    static if(!is(typeof(LDAP_URL_ERR_MEM))) {
        private enum enumMixinStr_LDAP_URL_ERR_MEM = `enum LDAP_URL_ERR_MEM = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_ERR_MEM); }))) {
            mixin(enumMixinStr_LDAP_URL_ERR_MEM);
        }
    }




    static if(!is(typeof(LDAP_URL_ERR_PARAM))) {
        private enum enumMixinStr_LDAP_URL_ERR_PARAM = `enum LDAP_URL_ERR_PARAM = 0x02;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_ERR_PARAM); }))) {
            mixin(enumMixinStr_LDAP_URL_ERR_PARAM);
        }
    }




    static if(!is(typeof(LDAP_URL_ERR_BADSCHEME))) {
        private enum enumMixinStr_LDAP_URL_ERR_BADSCHEME = `enum LDAP_URL_ERR_BADSCHEME = 0x03;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_ERR_BADSCHEME); }))) {
            mixin(enumMixinStr_LDAP_URL_ERR_BADSCHEME);
        }
    }




    static if(!is(typeof(LDAP_URL_ERR_BADENCLOSURE))) {
        private enum enumMixinStr_LDAP_URL_ERR_BADENCLOSURE = `enum LDAP_URL_ERR_BADENCLOSURE = 0x04;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_ERR_BADENCLOSURE); }))) {
            mixin(enumMixinStr_LDAP_URL_ERR_BADENCLOSURE);
        }
    }




    static if(!is(typeof(LDAP_URL_ERR_BADURL))) {
        private enum enumMixinStr_LDAP_URL_ERR_BADURL = `enum LDAP_URL_ERR_BADURL = 0x05;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_ERR_BADURL); }))) {
            mixin(enumMixinStr_LDAP_URL_ERR_BADURL);
        }
    }




    static if(!is(typeof(LDAP_URL_ERR_BADHOST))) {
        private enum enumMixinStr_LDAP_URL_ERR_BADHOST = `enum LDAP_URL_ERR_BADHOST = 0x06;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_ERR_BADHOST); }))) {
            mixin(enumMixinStr_LDAP_URL_ERR_BADHOST);
        }
    }




    static if(!is(typeof(LDAP_URL_ERR_BADATTRS))) {
        private enum enumMixinStr_LDAP_URL_ERR_BADATTRS = `enum LDAP_URL_ERR_BADATTRS = 0x07;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_ERR_BADATTRS); }))) {
            mixin(enumMixinStr_LDAP_URL_ERR_BADATTRS);
        }
    }




    static if(!is(typeof(LDAP_URL_ERR_BADSCOPE))) {
        private enum enumMixinStr_LDAP_URL_ERR_BADSCOPE = `enum LDAP_URL_ERR_BADSCOPE = 0x08;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_ERR_BADSCOPE); }))) {
            mixin(enumMixinStr_LDAP_URL_ERR_BADSCOPE);
        }
    }




    static if(!is(typeof(LDAP_URL_ERR_BADFILTER))) {
        private enum enumMixinStr_LDAP_URL_ERR_BADFILTER = `enum LDAP_URL_ERR_BADFILTER = 0x09;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_ERR_BADFILTER); }))) {
            mixin(enumMixinStr_LDAP_URL_ERR_BADFILTER);
        }
    }




    static if(!is(typeof(LDAP_URL_ERR_BADEXTS))) {
        private enum enumMixinStr_LDAP_URL_ERR_BADEXTS = `enum LDAP_URL_ERR_BADEXTS = 0x0a;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URL_ERR_BADEXTS); }))) {
            mixin(enumMixinStr_LDAP_URL_ERR_BADEXTS);
        }
    }




    static if(!is(typeof(LDAP_CLIENT_LOOP))) {
        private enum enumMixinStr_LDAP_CLIENT_LOOP = `enum LDAP_CLIENT_LOOP = ( - 16 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CLIENT_LOOP); }))) {
            mixin(enumMixinStr_LDAP_CLIENT_LOOP);
        }
    }




    static if(!is(typeof(LDAP_MORE_RESULTS_TO_RETURN))) {
        private enum enumMixinStr_LDAP_MORE_RESULTS_TO_RETURN = `enum LDAP_MORE_RESULTS_TO_RETURN = ( - 15 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MORE_RESULTS_TO_RETURN); }))) {
            mixin(enumMixinStr_LDAP_MORE_RESULTS_TO_RETURN);
        }
    }




    static if(!is(typeof(LDAP_NO_RESULTS_RETURNED))) {
        private enum enumMixinStr_LDAP_NO_RESULTS_RETURNED = `enum LDAP_NO_RESULTS_RETURNED = ( - 14 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NO_RESULTS_RETURNED); }))) {
            mixin(enumMixinStr_LDAP_NO_RESULTS_RETURNED);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_NOT_FOUND))) {
        private enum enumMixinStr_LDAP_CONTROL_NOT_FOUND = `enum LDAP_CONTROL_NOT_FOUND = ( - 13 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_NOT_FOUND); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_NOT_FOUND);
        }
    }




    static if(!is(typeof(LDAP_NOT_SUPPORTED))) {
        private enum enumMixinStr_LDAP_NOT_SUPPORTED = `enum LDAP_NOT_SUPPORTED = ( - 12 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NOT_SUPPORTED); }))) {
            mixin(enumMixinStr_LDAP_NOT_SUPPORTED);
        }
    }




    static if(!is(typeof(LDAP_CONNECT_ERROR))) {
        private enum enumMixinStr_LDAP_CONNECT_ERROR = `enum LDAP_CONNECT_ERROR = ( - 11 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONNECT_ERROR); }))) {
            mixin(enumMixinStr_LDAP_CONNECT_ERROR);
        }
    }




    static if(!is(typeof(LDAP_NO_MEMORY))) {
        private enum enumMixinStr_LDAP_NO_MEMORY = `enum LDAP_NO_MEMORY = ( - 10 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NO_MEMORY); }))) {
            mixin(enumMixinStr_LDAP_NO_MEMORY);
        }
    }




    static if(!is(typeof(LDAP_PARAM_ERROR))) {
        private enum enumMixinStr_LDAP_PARAM_ERROR = `enum LDAP_PARAM_ERROR = ( - 9 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_PARAM_ERROR); }))) {
            mixin(enumMixinStr_LDAP_PARAM_ERROR);
        }
    }




    static if(!is(typeof(LDAP_USER_CANCELLED))) {
        private enum enumMixinStr_LDAP_USER_CANCELLED = `enum LDAP_USER_CANCELLED = ( - 8 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_USER_CANCELLED); }))) {
            mixin(enumMixinStr_LDAP_USER_CANCELLED);
        }
    }




    static if(!is(typeof(LDAP_FILTER_ERROR))) {
        private enum enumMixinStr_LDAP_FILTER_ERROR = `enum LDAP_FILTER_ERROR = ( - 7 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_ERROR); }))) {
            mixin(enumMixinStr_LDAP_FILTER_ERROR);
        }
    }




    static if(!is(typeof(LDAP_AUTH_UNKNOWN))) {
        private enum enumMixinStr_LDAP_AUTH_UNKNOWN = `enum LDAP_AUTH_UNKNOWN = ( - 6 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_UNKNOWN); }))) {
            mixin(enumMixinStr_LDAP_AUTH_UNKNOWN);
        }
    }




    static if(!is(typeof(LDAP_TIMEOUT))) {
        private enum enumMixinStr_LDAP_TIMEOUT = `enum LDAP_TIMEOUT = ( - 5 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TIMEOUT); }))) {
            mixin(enumMixinStr_LDAP_TIMEOUT);
        }
    }




    static if(!is(typeof(LDAP_DECODING_ERROR))) {
        private enum enumMixinStr_LDAP_DECODING_ERROR = `enum LDAP_DECODING_ERROR = ( - 4 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DECODING_ERROR); }))) {
            mixin(enumMixinStr_LDAP_DECODING_ERROR);
        }
    }




    static if(!is(typeof(LDAP_ENCODING_ERROR))) {
        private enum enumMixinStr_LDAP_ENCODING_ERROR = `enum LDAP_ENCODING_ERROR = ( - 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_ENCODING_ERROR); }))) {
            mixin(enumMixinStr_LDAP_ENCODING_ERROR);
        }
    }




    static if(!is(typeof(LDAP_LOCAL_ERROR))) {
        private enum enumMixinStr_LDAP_LOCAL_ERROR = `enum LDAP_LOCAL_ERROR = ( - 2 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_LOCAL_ERROR); }))) {
            mixin(enumMixinStr_LDAP_LOCAL_ERROR);
        }
    }




    static if(!is(typeof(LDAP_SERVER_DOWN))) {
        private enum enumMixinStr_LDAP_SERVER_DOWN = `enum LDAP_SERVER_DOWN = ( - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SERVER_DOWN); }))) {
            mixin(enumMixinStr_LDAP_SERVER_DOWN);
        }
    }
    static if(!is(typeof(LDAP_X_INVALIDREFERENCE))) {
        private enum enumMixinStr_LDAP_X_INVALIDREFERENCE = `enum LDAP_X_INVALIDREFERENCE = 0x4112;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_X_INVALIDREFERENCE); }))) {
            mixin(enumMixinStr_LDAP_X_INVALIDREFERENCE);
        }
    }




    static if(!is(typeof(LDAP_X_CANNOT_CHAIN))) {
        private enum enumMixinStr_LDAP_X_CANNOT_CHAIN = `enum LDAP_X_CANNOT_CHAIN = 0x4111;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_X_CANNOT_CHAIN); }))) {
            mixin(enumMixinStr_LDAP_X_CANNOT_CHAIN);
        }
    }




    static if(!is(typeof(LDAP_X_NO_REFERRALS_FOUND))) {
        private enum enumMixinStr_LDAP_X_NO_REFERRALS_FOUND = `enum LDAP_X_NO_REFERRALS_FOUND = 0x4110;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_X_NO_REFERRALS_FOUND); }))) {
            mixin(enumMixinStr_LDAP_X_NO_REFERRALS_FOUND);
        }
    }




    static if(!is(typeof(LDAP_X_NO_OPERATION))) {
        private enum enumMixinStr_LDAP_X_NO_OPERATION = `enum LDAP_X_NO_OPERATION = 0x410e;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_X_NO_OPERATION); }))) {
            mixin(enumMixinStr_LDAP_X_NO_OPERATION);
        }
    }




    static if(!is(typeof(LDAP_X_ASSERTION_FAILED))) {
        private enum enumMixinStr_LDAP_X_ASSERTION_FAILED = `enum LDAP_X_ASSERTION_FAILED = 0x410f;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_X_ASSERTION_FAILED); }))) {
            mixin(enumMixinStr_LDAP_X_ASSERTION_FAILED);
        }
    }




    static if(!is(typeof(LDAP_X_SYNC_REFRESH_REQUIRED))) {
        private enum enumMixinStr_LDAP_X_SYNC_REFRESH_REQUIRED = `enum LDAP_X_SYNC_REFRESH_REQUIRED = 0x4100;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_X_SYNC_REFRESH_REQUIRED); }))) {
            mixin(enumMixinStr_LDAP_X_SYNC_REFRESH_REQUIRED);
        }
    }






    static if(!is(typeof(LDAP_SYNC_REFRESH_REQUIRED))) {
        private enum enumMixinStr_LDAP_SYNC_REFRESH_REQUIRED = `enum LDAP_SYNC_REFRESH_REQUIRED = 0x1000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_REFRESH_REQUIRED); }))) {
            mixin(enumMixinStr_LDAP_SYNC_REFRESH_REQUIRED);
        }
    }






    static if(!is(typeof(LDAP_PROXIED_AUTHORIZATION_DENIED))) {
        private enum enumMixinStr_LDAP_PROXIED_AUTHORIZATION_DENIED = `enum LDAP_PROXIED_AUTHORIZATION_DENIED = 0x7B;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_PROXIED_AUTHORIZATION_DENIED); }))) {
            mixin(enumMixinStr_LDAP_PROXIED_AUTHORIZATION_DENIED);
        }
    }




    static if(!is(typeof(LDAP_ASSERTION_FAILED))) {
        private enum enumMixinStr_LDAP_ASSERTION_FAILED = `enum LDAP_ASSERTION_FAILED = 0x7A;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_ASSERTION_FAILED); }))) {
            mixin(enumMixinStr_LDAP_ASSERTION_FAILED);
        }
    }




    static if(!is(typeof(LDAP_CANNOT_CANCEL))) {
        private enum enumMixinStr_LDAP_CANNOT_CANCEL = `enum LDAP_CANNOT_CANCEL = 0x79;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CANNOT_CANCEL); }))) {
            mixin(enumMixinStr_LDAP_CANNOT_CANCEL);
        }
    }




    static if(!is(typeof(LDAP_TOO_LATE))) {
        private enum enumMixinStr_LDAP_TOO_LATE = `enum LDAP_TOO_LATE = 0x78;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TOO_LATE); }))) {
            mixin(enumMixinStr_LDAP_TOO_LATE);
        }
    }




    static if(!is(typeof(LDAP_NO_SUCH_OPERATION))) {
        private enum enumMixinStr_LDAP_NO_SUCH_OPERATION = `enum LDAP_NO_SUCH_OPERATION = 0x77;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NO_SUCH_OPERATION); }))) {
            mixin(enumMixinStr_LDAP_NO_SUCH_OPERATION);
        }
    }




    static if(!is(typeof(LDAP_CANCELLED))) {
        private enum enumMixinStr_LDAP_CANCELLED = `enum LDAP_CANCELLED = 0x76;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CANCELLED); }))) {
            mixin(enumMixinStr_LDAP_CANCELLED);
        }
    }




    static if(!is(typeof(LDAP_CUP_RELOAD_REQUIRED))) {
        private enum enumMixinStr_LDAP_CUP_RELOAD_REQUIRED = `enum LDAP_CUP_RELOAD_REQUIRED = 0x75;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CUP_RELOAD_REQUIRED); }))) {
            mixin(enumMixinStr_LDAP_CUP_RELOAD_REQUIRED);
        }
    }




    static if(!is(typeof(LDAP_CUP_UNSUPPORTED_SCHEME))) {
        private enum enumMixinStr_LDAP_CUP_UNSUPPORTED_SCHEME = `enum LDAP_CUP_UNSUPPORTED_SCHEME = 0x74;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CUP_UNSUPPORTED_SCHEME); }))) {
            mixin(enumMixinStr_LDAP_CUP_UNSUPPORTED_SCHEME);
        }
    }




    static if(!is(typeof(LDAP_CUP_INVALID_DATA))) {
        private enum enumMixinStr_LDAP_CUP_INVALID_DATA = `enum LDAP_CUP_INVALID_DATA = 0x73;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CUP_INVALID_DATA); }))) {
            mixin(enumMixinStr_LDAP_CUP_INVALID_DATA);
        }
    }




    static if(!is(typeof(LDAP_CUP_SECURITY_VIOLATION))) {
        private enum enumMixinStr_LDAP_CUP_SECURITY_VIOLATION = `enum LDAP_CUP_SECURITY_VIOLATION = 0x72;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CUP_SECURITY_VIOLATION); }))) {
            mixin(enumMixinStr_LDAP_CUP_SECURITY_VIOLATION);
        }
    }




    static if(!is(typeof(LDAP_CUP_RESOURCES_EXHAUSTED))) {
        private enum enumMixinStr_LDAP_CUP_RESOURCES_EXHAUSTED = `enum LDAP_CUP_RESOURCES_EXHAUSTED = 0x71;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CUP_RESOURCES_EXHAUSTED); }))) {
            mixin(enumMixinStr_LDAP_CUP_RESOURCES_EXHAUSTED);
        }
    }




    static if(!is(typeof(LDAP_OTHER))) {
        private enum enumMixinStr_LDAP_OTHER = `enum LDAP_OTHER = 0x50;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OTHER); }))) {
            mixin(enumMixinStr_LDAP_OTHER);
        }
    }




    static if(!is(typeof(LDAP_VLV_ERROR))) {
        private enum enumMixinStr_LDAP_VLV_ERROR = `enum LDAP_VLV_ERROR = 0x4C;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VLV_ERROR); }))) {
            mixin(enumMixinStr_LDAP_VLV_ERROR);
        }
    }




    static if(!is(typeof(LDAP_AFFECTS_MULTIPLE_DSAS))) {
        private enum enumMixinStr_LDAP_AFFECTS_MULTIPLE_DSAS = `enum LDAP_AFFECTS_MULTIPLE_DSAS = 0x47;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AFFECTS_MULTIPLE_DSAS); }))) {
            mixin(enumMixinStr_LDAP_AFFECTS_MULTIPLE_DSAS);
        }
    }




    static if(!is(typeof(LDAP_RESULTS_TOO_LARGE))) {
        private enum enumMixinStr_LDAP_RESULTS_TOO_LARGE = `enum LDAP_RESULTS_TOO_LARGE = 0x46;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RESULTS_TOO_LARGE); }))) {
            mixin(enumMixinStr_LDAP_RESULTS_TOO_LARGE);
        }
    }




    static if(!is(typeof(LDAP_NO_OBJECT_CLASS_MODS))) {
        private enum enumMixinStr_LDAP_NO_OBJECT_CLASS_MODS = `enum LDAP_NO_OBJECT_CLASS_MODS = 0x45;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NO_OBJECT_CLASS_MODS); }))) {
            mixin(enumMixinStr_LDAP_NO_OBJECT_CLASS_MODS);
        }
    }




    static if(!is(typeof(LDAP_ALREADY_EXISTS))) {
        private enum enumMixinStr_LDAP_ALREADY_EXISTS = `enum LDAP_ALREADY_EXISTS = 0x44;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_ALREADY_EXISTS); }))) {
            mixin(enumMixinStr_LDAP_ALREADY_EXISTS);
        }
    }




    static if(!is(typeof(LDAP_NOT_ALLOWED_ON_RDN))) {
        private enum enumMixinStr_LDAP_NOT_ALLOWED_ON_RDN = `enum LDAP_NOT_ALLOWED_ON_RDN = 0x43;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NOT_ALLOWED_ON_RDN); }))) {
            mixin(enumMixinStr_LDAP_NOT_ALLOWED_ON_RDN);
        }
    }




    static if(!is(typeof(LDAP_NOT_ALLOWED_ON_NONLEAF))) {
        private enum enumMixinStr_LDAP_NOT_ALLOWED_ON_NONLEAF = `enum LDAP_NOT_ALLOWED_ON_NONLEAF = 0x42;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NOT_ALLOWED_ON_NONLEAF); }))) {
            mixin(enumMixinStr_LDAP_NOT_ALLOWED_ON_NONLEAF);
        }
    }




    static if(!is(typeof(LDAP_OBJECT_CLASS_VIOLATION))) {
        private enum enumMixinStr_LDAP_OBJECT_CLASS_VIOLATION = `enum LDAP_OBJECT_CLASS_VIOLATION = 0x41;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OBJECT_CLASS_VIOLATION); }))) {
            mixin(enumMixinStr_LDAP_OBJECT_CLASS_VIOLATION);
        }
    }




    static if(!is(typeof(LDAP_NAMING_VIOLATION))) {
        private enum enumMixinStr_LDAP_NAMING_VIOLATION = `enum LDAP_NAMING_VIOLATION = 0x40;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NAMING_VIOLATION); }))) {
            mixin(enumMixinStr_LDAP_NAMING_VIOLATION);
        }
    }






    static if(!is(typeof(LDAP_LOOP_DETECT))) {
        private enum enumMixinStr_LDAP_LOOP_DETECT = `enum LDAP_LOOP_DETECT = 0x36;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_LOOP_DETECT); }))) {
            mixin(enumMixinStr_LDAP_LOOP_DETECT);
        }
    }




    static if(!is(typeof(LDAP_UNWILLING_TO_PERFORM))) {
        private enum enumMixinStr_LDAP_UNWILLING_TO_PERFORM = `enum LDAP_UNWILLING_TO_PERFORM = 0x35;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_UNWILLING_TO_PERFORM); }))) {
            mixin(enumMixinStr_LDAP_UNWILLING_TO_PERFORM);
        }
    }




    static if(!is(typeof(LDAP_UNAVAILABLE))) {
        private enum enumMixinStr_LDAP_UNAVAILABLE = `enum LDAP_UNAVAILABLE = 0x34;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_UNAVAILABLE); }))) {
            mixin(enumMixinStr_LDAP_UNAVAILABLE);
        }
    }




    static if(!is(typeof(LDAP_BUSY))) {
        private enum enumMixinStr_LDAP_BUSY = `enum LDAP_BUSY = 0x33;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_BUSY); }))) {
            mixin(enumMixinStr_LDAP_BUSY);
        }
    }






    static if(!is(typeof(LDAP_INSUFFICIENT_ACCESS))) {
        private enum enumMixinStr_LDAP_INSUFFICIENT_ACCESS = `enum LDAP_INSUFFICIENT_ACCESS = 0x32;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_INSUFFICIENT_ACCESS); }))) {
            mixin(enumMixinStr_LDAP_INSUFFICIENT_ACCESS);
        }
    }




    static if(!is(typeof(LDAP_INVALID_CREDENTIALS))) {
        private enum enumMixinStr_LDAP_INVALID_CREDENTIALS = `enum LDAP_INVALID_CREDENTIALS = 0x31;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_INVALID_CREDENTIALS); }))) {
            mixin(enumMixinStr_LDAP_INVALID_CREDENTIALS);
        }
    }




    static if(!is(typeof(LDAP_INAPPROPRIATE_AUTH))) {
        private enum enumMixinStr_LDAP_INAPPROPRIATE_AUTH = `enum LDAP_INAPPROPRIATE_AUTH = 0x30;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_INAPPROPRIATE_AUTH); }))) {
            mixin(enumMixinStr_LDAP_INAPPROPRIATE_AUTH);
        }
    }




    static if(!is(typeof(LDAP_X_PROXY_AUTHZ_FAILURE))) {
        private enum enumMixinStr_LDAP_X_PROXY_AUTHZ_FAILURE = `enum LDAP_X_PROXY_AUTHZ_FAILURE = 0x2F;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_X_PROXY_AUTHZ_FAILURE); }))) {
            mixin(enumMixinStr_LDAP_X_PROXY_AUTHZ_FAILURE);
        }
    }






    static if(!is(typeof(LDAP_ALIAS_DEREF_PROBLEM))) {
        private enum enumMixinStr_LDAP_ALIAS_DEREF_PROBLEM = `enum LDAP_ALIAS_DEREF_PROBLEM = 0x24;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_ALIAS_DEREF_PROBLEM); }))) {
            mixin(enumMixinStr_LDAP_ALIAS_DEREF_PROBLEM);
        }
    }




    static if(!is(typeof(LDAP_IS_LEAF))) {
        private enum enumMixinStr_LDAP_IS_LEAF = `enum LDAP_IS_LEAF = 0x23;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_IS_LEAF); }))) {
            mixin(enumMixinStr_LDAP_IS_LEAF);
        }
    }




    static if(!is(typeof(LDAP_INVALID_DN_SYNTAX))) {
        private enum enumMixinStr_LDAP_INVALID_DN_SYNTAX = `enum LDAP_INVALID_DN_SYNTAX = 0x22;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_INVALID_DN_SYNTAX); }))) {
            mixin(enumMixinStr_LDAP_INVALID_DN_SYNTAX);
        }
    }




    static if(!is(typeof(LDAP_ALIAS_PROBLEM))) {
        private enum enumMixinStr_LDAP_ALIAS_PROBLEM = `enum LDAP_ALIAS_PROBLEM = 0x21;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_ALIAS_PROBLEM); }))) {
            mixin(enumMixinStr_LDAP_ALIAS_PROBLEM);
        }
    }




    static if(!is(typeof(LDAP_NO_SUCH_OBJECT))) {
        private enum enumMixinStr_LDAP_NO_SUCH_OBJECT = `enum LDAP_NO_SUCH_OBJECT = 0x20;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NO_SUCH_OBJECT); }))) {
            mixin(enumMixinStr_LDAP_NO_SUCH_OBJECT);
        }
    }






    static if(!is(typeof(LDAP_INVALID_SYNTAX))) {
        private enum enumMixinStr_LDAP_INVALID_SYNTAX = `enum LDAP_INVALID_SYNTAX = 0x15;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_INVALID_SYNTAX); }))) {
            mixin(enumMixinStr_LDAP_INVALID_SYNTAX);
        }
    }




    static if(!is(typeof(LDAP_TYPE_OR_VALUE_EXISTS))) {
        private enum enumMixinStr_LDAP_TYPE_OR_VALUE_EXISTS = `enum LDAP_TYPE_OR_VALUE_EXISTS = 0x14;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TYPE_OR_VALUE_EXISTS); }))) {
            mixin(enumMixinStr_LDAP_TYPE_OR_VALUE_EXISTS);
        }
    }




    static if(!is(typeof(LDAP_CONSTRAINT_VIOLATION))) {
        private enum enumMixinStr_LDAP_CONSTRAINT_VIOLATION = `enum LDAP_CONSTRAINT_VIOLATION = 0x13;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONSTRAINT_VIOLATION); }))) {
            mixin(enumMixinStr_LDAP_CONSTRAINT_VIOLATION);
        }
    }




    static if(!is(typeof(LDAP_INAPPROPRIATE_MATCHING))) {
        private enum enumMixinStr_LDAP_INAPPROPRIATE_MATCHING = `enum LDAP_INAPPROPRIATE_MATCHING = 0x12;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_INAPPROPRIATE_MATCHING); }))) {
            mixin(enumMixinStr_LDAP_INAPPROPRIATE_MATCHING);
        }
    }




    static if(!is(typeof(LDAP_UNDEFINED_TYPE))) {
        private enum enumMixinStr_LDAP_UNDEFINED_TYPE = `enum LDAP_UNDEFINED_TYPE = 0x11;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_UNDEFINED_TYPE); }))) {
            mixin(enumMixinStr_LDAP_UNDEFINED_TYPE);
        }
    }




    static if(!is(typeof(LDAP_NO_SUCH_ATTRIBUTE))) {
        private enum enumMixinStr_LDAP_NO_SUCH_ATTRIBUTE = `enum LDAP_NO_SUCH_ATTRIBUTE = 0x10;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NO_SUCH_ATTRIBUTE); }))) {
            mixin(enumMixinStr_LDAP_NO_SUCH_ATTRIBUTE);
        }
    }






    static if(!is(typeof(LDAP_SASL_BIND_IN_PROGRESS))) {
        private enum enumMixinStr_LDAP_SASL_BIND_IN_PROGRESS = `enum LDAP_SASL_BIND_IN_PROGRESS = 0x0e;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SASL_BIND_IN_PROGRESS); }))) {
            mixin(enumMixinStr_LDAP_SASL_BIND_IN_PROGRESS);
        }
    }




    static if(!is(typeof(LDAP_CONFIDENTIALITY_REQUIRED))) {
        private enum enumMixinStr_LDAP_CONFIDENTIALITY_REQUIRED = `enum LDAP_CONFIDENTIALITY_REQUIRED = 0x0d;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONFIDENTIALITY_REQUIRED); }))) {
            mixin(enumMixinStr_LDAP_CONFIDENTIALITY_REQUIRED);
        }
    }




    static if(!is(typeof(LDAP_UNAVAILABLE_CRITICAL_EXTENSION))) {
        private enum enumMixinStr_LDAP_UNAVAILABLE_CRITICAL_EXTENSION = `enum LDAP_UNAVAILABLE_CRITICAL_EXTENSION = 0x0c;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_UNAVAILABLE_CRITICAL_EXTENSION); }))) {
            mixin(enumMixinStr_LDAP_UNAVAILABLE_CRITICAL_EXTENSION);
        }
    }




    static if(!is(typeof(LDAP_ADMINLIMIT_EXCEEDED))) {
        private enum enumMixinStr_LDAP_ADMINLIMIT_EXCEEDED = `enum LDAP_ADMINLIMIT_EXCEEDED = 0x0b;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_ADMINLIMIT_EXCEEDED); }))) {
            mixin(enumMixinStr_LDAP_ADMINLIMIT_EXCEEDED);
        }
    }




    static if(!is(typeof(LDAP_REFERRAL))) {
        private enum enumMixinStr_LDAP_REFERRAL = `enum LDAP_REFERRAL = 0x0a;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REFERRAL); }))) {
            mixin(enumMixinStr_LDAP_REFERRAL);
        }
    }




    static if(!is(typeof(LDAP_PARTIAL_RESULTS))) {
        private enum enumMixinStr_LDAP_PARTIAL_RESULTS = `enum LDAP_PARTIAL_RESULTS = 0x09;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_PARTIAL_RESULTS); }))) {
            mixin(enumMixinStr_LDAP_PARTIAL_RESULTS);
        }
    }




    static if(!is(typeof(LDAP_STRONGER_AUTH_REQUIRED))) {
        private enum enumMixinStr_LDAP_STRONGER_AUTH_REQUIRED = `enum LDAP_STRONGER_AUTH_REQUIRED = LDAP_STRONG_AUTH_REQUIRED;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_STRONGER_AUTH_REQUIRED); }))) {
            mixin(enumMixinStr_LDAP_STRONGER_AUTH_REQUIRED);
        }
    }




    static if(!is(typeof(LDAP_STRONG_AUTH_REQUIRED))) {
        private enum enumMixinStr_LDAP_STRONG_AUTH_REQUIRED = `enum LDAP_STRONG_AUTH_REQUIRED = 0x08;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_STRONG_AUTH_REQUIRED); }))) {
            mixin(enumMixinStr_LDAP_STRONG_AUTH_REQUIRED);
        }
    }




    static if(!is(typeof(LDAP_STRONG_AUTH_NOT_SUPPORTED))) {
        private enum enumMixinStr_LDAP_STRONG_AUTH_NOT_SUPPORTED = `enum LDAP_STRONG_AUTH_NOT_SUPPORTED = LDAP_AUTH_METHOD_NOT_SUPPORTED;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_STRONG_AUTH_NOT_SUPPORTED); }))) {
            mixin(enumMixinStr_LDAP_STRONG_AUTH_NOT_SUPPORTED);
        }
    }




    static if(!is(typeof(LDAP_AUTH_METHOD_NOT_SUPPORTED))) {
        private enum enumMixinStr_LDAP_AUTH_METHOD_NOT_SUPPORTED = `enum LDAP_AUTH_METHOD_NOT_SUPPORTED = 0x07;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_METHOD_NOT_SUPPORTED); }))) {
            mixin(enumMixinStr_LDAP_AUTH_METHOD_NOT_SUPPORTED);
        }
    }




    static if(!is(typeof(LDAP_COMPARE_TRUE))) {
        private enum enumMixinStr_LDAP_COMPARE_TRUE = `enum LDAP_COMPARE_TRUE = 0x06;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_COMPARE_TRUE); }))) {
            mixin(enumMixinStr_LDAP_COMPARE_TRUE);
        }
    }




    static if(!is(typeof(LDAP_COMPARE_FALSE))) {
        private enum enumMixinStr_LDAP_COMPARE_FALSE = `enum LDAP_COMPARE_FALSE = 0x05;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_COMPARE_FALSE); }))) {
            mixin(enumMixinStr_LDAP_COMPARE_FALSE);
        }
    }




    static if(!is(typeof(LDAP_SIZELIMIT_EXCEEDED))) {
        private enum enumMixinStr_LDAP_SIZELIMIT_EXCEEDED = `enum LDAP_SIZELIMIT_EXCEEDED = 0x04;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SIZELIMIT_EXCEEDED); }))) {
            mixin(enumMixinStr_LDAP_SIZELIMIT_EXCEEDED);
        }
    }




    static if(!is(typeof(LDAP_TIMELIMIT_EXCEEDED))) {
        private enum enumMixinStr_LDAP_TIMELIMIT_EXCEEDED = `enum LDAP_TIMELIMIT_EXCEEDED = 0x03;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TIMELIMIT_EXCEEDED); }))) {
            mixin(enumMixinStr_LDAP_TIMELIMIT_EXCEEDED);
        }
    }




    static if(!is(typeof(LDAP_PROTOCOL_ERROR))) {
        private enum enumMixinStr_LDAP_PROTOCOL_ERROR = `enum LDAP_PROTOCOL_ERROR = 0x02;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_PROTOCOL_ERROR); }))) {
            mixin(enumMixinStr_LDAP_PROTOCOL_ERROR);
        }
    }




    static if(!is(typeof(LDAP_OPERATIONS_ERROR))) {
        private enum enumMixinStr_LDAP_OPERATIONS_ERROR = `enum LDAP_OPERATIONS_ERROR = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPERATIONS_ERROR); }))) {
            mixin(enumMixinStr_LDAP_OPERATIONS_ERROR);
        }
    }






    static if(!is(typeof(LDAP_SUCCESS))) {
        private enum enumMixinStr_LDAP_SUCCESS = `enum LDAP_SUCCESS = 0x00;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SUCCESS); }))) {
            mixin(enumMixinStr_LDAP_SUCCESS);
        }
    }




    static if(!is(typeof(LDAP_SUBSTRING_FINAL))) {
        private enum enumMixinStr_LDAP_SUBSTRING_FINAL = `enum LDAP_SUBSTRING_FINAL = ( cast( ber_tag_t ) 0x82U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SUBSTRING_FINAL); }))) {
            mixin(enumMixinStr_LDAP_SUBSTRING_FINAL);
        }
    }




    static if(!is(typeof(LDAP_SUBSTRING_ANY))) {
        private enum enumMixinStr_LDAP_SUBSTRING_ANY = `enum LDAP_SUBSTRING_ANY = ( cast( ber_tag_t ) 0x81U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SUBSTRING_ANY); }))) {
            mixin(enumMixinStr_LDAP_SUBSTRING_ANY);
        }
    }




    static if(!is(typeof(LDAP_SUBSTRING_INITIAL))) {
        private enum enumMixinStr_LDAP_SUBSTRING_INITIAL = `enum LDAP_SUBSTRING_INITIAL = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SUBSTRING_INITIAL); }))) {
            mixin(enumMixinStr_LDAP_SUBSTRING_INITIAL);
        }
    }




    static if(!is(typeof(LDAP_SCOPE_DEFAULT))) {
        private enum enumMixinStr_LDAP_SCOPE_DEFAULT = `enum LDAP_SCOPE_DEFAULT = ( cast( ber_int_t ) - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SCOPE_DEFAULT); }))) {
            mixin(enumMixinStr_LDAP_SCOPE_DEFAULT);
        }
    }




    static if(!is(typeof(LDAP_SCOPE_CHILDREN))) {
        private enum enumMixinStr_LDAP_SCOPE_CHILDREN = `enum LDAP_SCOPE_CHILDREN = LDAP_SCOPE_SUBORDINATE;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SCOPE_CHILDREN); }))) {
            mixin(enumMixinStr_LDAP_SCOPE_CHILDREN);
        }
    }




    static if(!is(typeof(LDAP_SCOPE_SUBORDINATE))) {
        private enum enumMixinStr_LDAP_SCOPE_SUBORDINATE = `enum LDAP_SCOPE_SUBORDINATE = ( cast( ber_int_t ) 0x0003 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SCOPE_SUBORDINATE); }))) {
            mixin(enumMixinStr_LDAP_SCOPE_SUBORDINATE);
        }
    }




    static if(!is(typeof(LDAP_SCOPE_SUB))) {
        private enum enumMixinStr_LDAP_SCOPE_SUB = `enum LDAP_SCOPE_SUB = LDAP_SCOPE_SUBTREE;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SCOPE_SUB); }))) {
            mixin(enumMixinStr_LDAP_SCOPE_SUB);
        }
    }




    static if(!is(typeof(LDAP_SCOPE_SUBTREE))) {
        private enum enumMixinStr_LDAP_SCOPE_SUBTREE = `enum LDAP_SCOPE_SUBTREE = ( cast( ber_int_t ) 0x0002 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SCOPE_SUBTREE); }))) {
            mixin(enumMixinStr_LDAP_SCOPE_SUBTREE);
        }
    }




    static if(!is(typeof(LDAP_SCOPE_ONE))) {
        private enum enumMixinStr_LDAP_SCOPE_ONE = `enum LDAP_SCOPE_ONE = LDAP_SCOPE_ONELEVEL;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SCOPE_ONE); }))) {
            mixin(enumMixinStr_LDAP_SCOPE_ONE);
        }
    }




    static if(!is(typeof(LDAP_SCOPE_ONELEVEL))) {
        private enum enumMixinStr_LDAP_SCOPE_ONELEVEL = `enum LDAP_SCOPE_ONELEVEL = ( cast( ber_int_t ) 0x0001 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SCOPE_ONELEVEL); }))) {
            mixin(enumMixinStr_LDAP_SCOPE_ONELEVEL);
        }
    }




    static if(!is(typeof(LDAP_SCOPE_BASEOBJECT))) {
        private enum enumMixinStr_LDAP_SCOPE_BASEOBJECT = `enum LDAP_SCOPE_BASEOBJECT = LDAP_SCOPE_BASE;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SCOPE_BASEOBJECT); }))) {
            mixin(enumMixinStr_LDAP_SCOPE_BASEOBJECT);
        }
    }




    static if(!is(typeof(LDAP_SCOPE_BASE))) {
        private enum enumMixinStr_LDAP_SCOPE_BASE = `enum LDAP_SCOPE_BASE = ( cast( ber_int_t ) 0x0000 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SCOPE_BASE); }))) {
            mixin(enumMixinStr_LDAP_SCOPE_BASE);
        }
    }




    static if(!is(typeof(LDAP_FILTER_EXT_DNATTRS))) {
        private enum enumMixinStr_LDAP_FILTER_EXT_DNATTRS = `enum LDAP_FILTER_EXT_DNATTRS = ( cast( ber_tag_t ) 0x84U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_EXT_DNATTRS); }))) {
            mixin(enumMixinStr_LDAP_FILTER_EXT_DNATTRS);
        }
    }




    static if(!is(typeof(LDAP_FILTER_EXT_VALUE))) {
        private enum enumMixinStr_LDAP_FILTER_EXT_VALUE = `enum LDAP_FILTER_EXT_VALUE = ( cast( ber_tag_t ) 0x83U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_EXT_VALUE); }))) {
            mixin(enumMixinStr_LDAP_FILTER_EXT_VALUE);
        }
    }




    static if(!is(typeof(LDAP_FILTER_EXT_TYPE))) {
        private enum enumMixinStr_LDAP_FILTER_EXT_TYPE = `enum LDAP_FILTER_EXT_TYPE = ( cast( ber_tag_t ) 0x82U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_EXT_TYPE); }))) {
            mixin(enumMixinStr_LDAP_FILTER_EXT_TYPE);
        }
    }




    static if(!is(typeof(LDAP_FILTER_EXT_OID))) {
        private enum enumMixinStr_LDAP_FILTER_EXT_OID = `enum LDAP_FILTER_EXT_OID = ( cast( ber_tag_t ) 0x81U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_EXT_OID); }))) {
            mixin(enumMixinStr_LDAP_FILTER_EXT_OID);
        }
    }




    static if(!is(typeof(LDAP_FILTER_EXT))) {
        private enum enumMixinStr_LDAP_FILTER_EXT = `enum LDAP_FILTER_EXT = ( cast( ber_tag_t ) 0xa9U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_EXT); }))) {
            mixin(enumMixinStr_LDAP_FILTER_EXT);
        }
    }




    static if(!is(typeof(LDAP_FILTER_APPROX))) {
        private enum enumMixinStr_LDAP_FILTER_APPROX = `enum LDAP_FILTER_APPROX = ( cast( ber_tag_t ) 0xa8U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_APPROX); }))) {
            mixin(enumMixinStr_LDAP_FILTER_APPROX);
        }
    }




    static if(!is(typeof(LDAP_SASL_AUTOMATIC))) {
        private enum enumMixinStr_LDAP_SASL_AUTOMATIC = `enum LDAP_SASL_AUTOMATIC = 0U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SASL_AUTOMATIC); }))) {
            mixin(enumMixinStr_LDAP_SASL_AUTOMATIC);
        }
    }




    static if(!is(typeof(LDAP_SASL_INTERACTIVE))) {
        private enum enumMixinStr_LDAP_SASL_INTERACTIVE = `enum LDAP_SASL_INTERACTIVE = 1U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SASL_INTERACTIVE); }))) {
            mixin(enumMixinStr_LDAP_SASL_INTERACTIVE);
        }
    }




    static if(!is(typeof(LDAP_SASL_QUIET))) {
        private enum enumMixinStr_LDAP_SASL_QUIET = `enum LDAP_SASL_QUIET = 2U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SASL_QUIET); }))) {
            mixin(enumMixinStr_LDAP_SASL_QUIET);
        }
    }




    static if(!is(typeof(LDAP_FILTER_PRESENT))) {
        private enum enumMixinStr_LDAP_FILTER_PRESENT = `enum LDAP_FILTER_PRESENT = ( cast( ber_tag_t ) 0x87U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_PRESENT); }))) {
            mixin(enumMixinStr_LDAP_FILTER_PRESENT);
        }
    }




    static if(!is(typeof(LDAP_FILTER_LE))) {
        private enum enumMixinStr_LDAP_FILTER_LE = `enum LDAP_FILTER_LE = ( cast( ber_tag_t ) 0xa6U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_LE); }))) {
            mixin(enumMixinStr_LDAP_FILTER_LE);
        }
    }




    static if(!is(typeof(LDAP_FILTER_GE))) {
        private enum enumMixinStr_LDAP_FILTER_GE = `enum LDAP_FILTER_GE = ( cast( ber_tag_t ) 0xa5U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_GE); }))) {
            mixin(enumMixinStr_LDAP_FILTER_GE);
        }
    }




    static if(!is(typeof(LDAP_FILTER_SUBSTRINGS))) {
        private enum enumMixinStr_LDAP_FILTER_SUBSTRINGS = `enum LDAP_FILTER_SUBSTRINGS = ( cast( ber_tag_t ) 0xa4U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_SUBSTRINGS); }))) {
            mixin(enumMixinStr_LDAP_FILTER_SUBSTRINGS);
        }
    }




    static if(!is(typeof(LDAP_FILTER_EQUALITY))) {
        private enum enumMixinStr_LDAP_FILTER_EQUALITY = `enum LDAP_FILTER_EQUALITY = ( cast( ber_tag_t ) 0xa3U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_EQUALITY); }))) {
            mixin(enumMixinStr_LDAP_FILTER_EQUALITY);
        }
    }




    static if(!is(typeof(LDAP_FILTER_NOT))) {
        private enum enumMixinStr_LDAP_FILTER_NOT = `enum LDAP_FILTER_NOT = ( cast( ber_tag_t ) 0xa2U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_NOT); }))) {
            mixin(enumMixinStr_LDAP_FILTER_NOT);
        }
    }




    static if(!is(typeof(LDAP_FILTER_OR))) {
        private enum enumMixinStr_LDAP_FILTER_OR = `enum LDAP_FILTER_OR = ( cast( ber_tag_t ) 0xa1U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_OR); }))) {
            mixin(enumMixinStr_LDAP_FILTER_OR);
        }
    }




    static if(!is(typeof(LDAP_FILTER_AND))) {
        private enum enumMixinStr_LDAP_FILTER_AND = `enum LDAP_FILTER_AND = ( cast( ber_tag_t ) 0xa0U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FILTER_AND); }))) {
            mixin(enumMixinStr_LDAP_FILTER_AND);
        }
    }




    static if(!is(typeof(LDAP_AUTH_NEGOTIATE))) {
        private enum enumMixinStr_LDAP_AUTH_NEGOTIATE = `enum LDAP_AUTH_NEGOTIATE = ( cast( ber_tag_t ) 0x04FFU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_NEGOTIATE); }))) {
            mixin(enumMixinStr_LDAP_AUTH_NEGOTIATE);
        }
    }




    static if(!is(typeof(LDAP_AUTH_KRBV42))) {
        private enum enumMixinStr_LDAP_AUTH_KRBV42 = `enum LDAP_AUTH_KRBV42 = ( cast( ber_tag_t ) 0x82U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_KRBV42); }))) {
            mixin(enumMixinStr_LDAP_AUTH_KRBV42);
        }
    }




    static if(!is(typeof(LDAP_AUTH_KRBV41))) {
        private enum enumMixinStr_LDAP_AUTH_KRBV41 = `enum LDAP_AUTH_KRBV41 = ( cast( ber_tag_t ) 0x81U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_KRBV41); }))) {
            mixin(enumMixinStr_LDAP_AUTH_KRBV41);
        }
    }




    static if(!is(typeof(LDAP_AUTH_KRBV4))) {
        private enum enumMixinStr_LDAP_AUTH_KRBV4 = `enum LDAP_AUTH_KRBV4 = ( cast( ber_tag_t ) 0xffU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_KRBV4); }))) {
            mixin(enumMixinStr_LDAP_AUTH_KRBV4);
        }
    }




    static if(!is(typeof(LDAP_AUTH_SASL))) {
        private enum enumMixinStr_LDAP_AUTH_SASL = `enum LDAP_AUTH_SASL = ( cast( ber_tag_t ) 0xa3U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_SASL); }))) {
            mixin(enumMixinStr_LDAP_AUTH_SASL);
        }
    }




    static if(!is(typeof(LDAP_AUTH_SIMPLE))) {
        private enum enumMixinStr_LDAP_AUTH_SIMPLE = `enum LDAP_AUTH_SIMPLE = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_SIMPLE); }))) {
            mixin(enumMixinStr_LDAP_AUTH_SIMPLE);
        }
    }




    static if(!is(typeof(LDAP_AUTH_NONE))) {
        private enum enumMixinStr_LDAP_AUTH_NONE = `enum LDAP_AUTH_NONE = ( cast( ber_tag_t ) 0x00U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_NONE); }))) {
            mixin(enumMixinStr_LDAP_AUTH_NONE);
        }
    }




    static if(!is(typeof(LDAP_SASL_NULL))) {
        private enum enumMixinStr_LDAP_SASL_NULL = `enum LDAP_SASL_NULL = ( "" );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SASL_NULL); }))) {
            mixin(enumMixinStr_LDAP_SASL_NULL);
        }
    }




    static if(!is(typeof(LDAP_SASL_SIMPLE))) {
        private enum enumMixinStr_LDAP_SASL_SIMPLE = `enum LDAP_SASL_SIMPLE = ( cast( char * ) 0 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SASL_SIMPLE); }))) {
            mixin(enumMixinStr_LDAP_SASL_SIMPLE);
        }
    }




    static if(!is(typeof(LDAP_RES_UNSOLICITED))) {
        private enum enumMixinStr_LDAP_RES_UNSOLICITED = `enum LDAP_RES_UNSOLICITED = ( 0 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_UNSOLICITED); }))) {
            mixin(enumMixinStr_LDAP_RES_UNSOLICITED);
        }
    }




    static if(!is(typeof(LDAP_RES_ANY))) {
        private enum enumMixinStr_LDAP_RES_ANY = `enum LDAP_RES_ANY = ( - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_ANY); }))) {
            mixin(enumMixinStr_LDAP_RES_ANY);
        }
    }




    static if(!is(typeof(LDAP_RES_INTERMEDIATE))) {
        private enum enumMixinStr_LDAP_RES_INTERMEDIATE = `enum LDAP_RES_INTERMEDIATE = ( cast( ber_tag_t ) 0x79U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_INTERMEDIATE); }))) {
            mixin(enumMixinStr_LDAP_RES_INTERMEDIATE);
        }
    }




    static if(!is(typeof(LDAP_RES_EXTENDED))) {
        private enum enumMixinStr_LDAP_RES_EXTENDED = `enum LDAP_RES_EXTENDED = ( cast( ber_tag_t ) 0x78U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_EXTENDED); }))) {
            mixin(enumMixinStr_LDAP_RES_EXTENDED);
        }
    }




    static if(!is(typeof(LDAP_RES_COMPARE))) {
        private enum enumMixinStr_LDAP_RES_COMPARE = `enum LDAP_RES_COMPARE = ( cast( ber_tag_t ) 0x6fU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_COMPARE); }))) {
            mixin(enumMixinStr_LDAP_RES_COMPARE);
        }
    }




    static if(!is(typeof(LDAP_RES_RENAME))) {
        private enum enumMixinStr_LDAP_RES_RENAME = `enum LDAP_RES_RENAME = LDAP_RES_MODDN;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_RENAME); }))) {
            mixin(enumMixinStr_LDAP_RES_RENAME);
        }
    }




    static if(!is(typeof(LDAP_RES_MODRDN))) {
        private enum enumMixinStr_LDAP_RES_MODRDN = `enum LDAP_RES_MODRDN = LDAP_RES_MODDN;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_MODRDN); }))) {
            mixin(enumMixinStr_LDAP_RES_MODRDN);
        }
    }




    static if(!is(typeof(LDAP_RES_MODDN))) {
        private enum enumMixinStr_LDAP_RES_MODDN = `enum LDAP_RES_MODDN = ( cast( ber_tag_t ) 0x6dU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_MODDN); }))) {
            mixin(enumMixinStr_LDAP_RES_MODDN);
        }
    }




    static if(!is(typeof(LDAP_RES_DELETE))) {
        private enum enumMixinStr_LDAP_RES_DELETE = `enum LDAP_RES_DELETE = ( cast( ber_tag_t ) 0x6bU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_DELETE); }))) {
            mixin(enumMixinStr_LDAP_RES_DELETE);
        }
    }




    static if(!is(typeof(LDAP_RES_ADD))) {
        private enum enumMixinStr_LDAP_RES_ADD = `enum LDAP_RES_ADD = ( cast( ber_tag_t ) 0x69U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_ADD); }))) {
            mixin(enumMixinStr_LDAP_RES_ADD);
        }
    }




    static if(!is(typeof(LDAP_RES_MODIFY))) {
        private enum enumMixinStr_LDAP_RES_MODIFY = `enum LDAP_RES_MODIFY = ( cast( ber_tag_t ) 0x67U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_MODIFY); }))) {
            mixin(enumMixinStr_LDAP_RES_MODIFY);
        }
    }




    static if(!is(typeof(LDAP_RES_SEARCH_RESULT))) {
        private enum enumMixinStr_LDAP_RES_SEARCH_RESULT = `enum LDAP_RES_SEARCH_RESULT = ( cast( ber_tag_t ) 0x65U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_SEARCH_RESULT); }))) {
            mixin(enumMixinStr_LDAP_RES_SEARCH_RESULT);
        }
    }




    static if(!is(typeof(LDAP_RES_SEARCH_REFERENCE))) {
        private enum enumMixinStr_LDAP_RES_SEARCH_REFERENCE = `enum LDAP_RES_SEARCH_REFERENCE = ( cast( ber_tag_t ) 0x73U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_SEARCH_REFERENCE); }))) {
            mixin(enumMixinStr_LDAP_RES_SEARCH_REFERENCE);
        }
    }




    static if(!is(typeof(LDAP_RES_SEARCH_ENTRY))) {
        private enum enumMixinStr_LDAP_RES_SEARCH_ENTRY = `enum LDAP_RES_SEARCH_ENTRY = ( cast( ber_tag_t ) 0x64U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_SEARCH_ENTRY); }))) {
            mixin(enumMixinStr_LDAP_RES_SEARCH_ENTRY);
        }
    }




    static if(!is(typeof(LDAP_RES_BIND))) {
        private enum enumMixinStr_LDAP_RES_BIND = `enum LDAP_RES_BIND = ( cast( ber_tag_t ) 0x61U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_RES_BIND); }))) {
            mixin(enumMixinStr_LDAP_RES_BIND);
        }
    }




    static if(!is(typeof(LDAP_REQ_EXTENDED))) {
        private enum enumMixinStr_LDAP_REQ_EXTENDED = `enum LDAP_REQ_EXTENDED = ( cast( ber_tag_t ) 0x77U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_EXTENDED); }))) {
            mixin(enumMixinStr_LDAP_REQ_EXTENDED);
        }
    }




    static if(!is(typeof(LDAP_REQ_ABANDON))) {
        private enum enumMixinStr_LDAP_REQ_ABANDON = `enum LDAP_REQ_ABANDON = ( cast( ber_tag_t ) 0x50U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_ABANDON); }))) {
            mixin(enumMixinStr_LDAP_REQ_ABANDON);
        }
    }




    static if(!is(typeof(LDAP_REQ_COMPARE))) {
        private enum enumMixinStr_LDAP_REQ_COMPARE = `enum LDAP_REQ_COMPARE = ( cast( ber_tag_t ) 0x6eU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_COMPARE); }))) {
            mixin(enumMixinStr_LDAP_REQ_COMPARE);
        }
    }




    static if(!is(typeof(LDAP_REQ_RENAME))) {
        private enum enumMixinStr_LDAP_REQ_RENAME = `enum LDAP_REQ_RENAME = LDAP_REQ_MODDN;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_RENAME); }))) {
            mixin(enumMixinStr_LDAP_REQ_RENAME);
        }
    }




    static if(!is(typeof(LDAP_REQ_MODRDN))) {
        private enum enumMixinStr_LDAP_REQ_MODRDN = `enum LDAP_REQ_MODRDN = LDAP_REQ_MODDN;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_MODRDN); }))) {
            mixin(enumMixinStr_LDAP_REQ_MODRDN);
        }
    }




    static if(!is(typeof(LDAP_REQ_MODDN))) {
        private enum enumMixinStr_LDAP_REQ_MODDN = `enum LDAP_REQ_MODDN = ( cast( ber_tag_t ) 0x6cU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_MODDN); }))) {
            mixin(enumMixinStr_LDAP_REQ_MODDN);
        }
    }




    static if(!is(typeof(LDAP_REQ_DELETE))) {
        private enum enumMixinStr_LDAP_REQ_DELETE = `enum LDAP_REQ_DELETE = ( cast( ber_tag_t ) 0x4aU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_DELETE); }))) {
            mixin(enumMixinStr_LDAP_REQ_DELETE);
        }
    }




    static if(!is(typeof(LDAP_REQ_ADD))) {
        private enum enumMixinStr_LDAP_REQ_ADD = `enum LDAP_REQ_ADD = ( cast( ber_tag_t ) 0x68U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_ADD); }))) {
            mixin(enumMixinStr_LDAP_REQ_ADD);
        }
    }




    static if(!is(typeof(LDAP_REQ_MODIFY))) {
        private enum enumMixinStr_LDAP_REQ_MODIFY = `enum LDAP_REQ_MODIFY = ( cast( ber_tag_t ) 0x66U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_MODIFY); }))) {
            mixin(enumMixinStr_LDAP_REQ_MODIFY);
        }
    }




    static if(!is(typeof(LDAP_REQ_SEARCH))) {
        private enum enumMixinStr_LDAP_REQ_SEARCH = `enum LDAP_REQ_SEARCH = ( cast( ber_tag_t ) 0x63U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_SEARCH); }))) {
            mixin(enumMixinStr_LDAP_REQ_SEARCH);
        }
    }




    static if(!is(typeof(LDAP_REQ_UNBIND))) {
        private enum enumMixinStr_LDAP_REQ_UNBIND = `enum LDAP_REQ_UNBIND = ( cast( ber_tag_t ) 0x42U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_UNBIND); }))) {
            mixin(enumMixinStr_LDAP_REQ_UNBIND);
        }
    }




    static if(!is(typeof(LDAP_REQ_BIND))) {
        private enum enumMixinStr_LDAP_REQ_BIND = `enum LDAP_REQ_BIND = ( cast( ber_tag_t ) 0x60U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REQ_BIND); }))) {
            mixin(enumMixinStr_LDAP_REQ_BIND);
        }
    }




    static if(!is(typeof(LDAP_TAG_SASL_RES_CREDS))) {
        private enum enumMixinStr_LDAP_TAG_SASL_RES_CREDS = `enum LDAP_TAG_SASL_RES_CREDS = ( cast( ber_tag_t ) 0x87U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_SASL_RES_CREDS); }))) {
            mixin(enumMixinStr_LDAP_TAG_SASL_RES_CREDS);
        }
    }




    static if(!is(typeof(LDAP_TAG_IM_RES_VALUE))) {
        private enum enumMixinStr_LDAP_TAG_IM_RES_VALUE = `enum LDAP_TAG_IM_RES_VALUE = ( cast( ber_tag_t ) 0x81U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_IM_RES_VALUE); }))) {
            mixin(enumMixinStr_LDAP_TAG_IM_RES_VALUE);
        }
    }




    static if(!is(typeof(LDAP_TAG_IM_RES_OID))) {
        private enum enumMixinStr_LDAP_TAG_IM_RES_OID = `enum LDAP_TAG_IM_RES_OID = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_IM_RES_OID); }))) {
            mixin(enumMixinStr_LDAP_TAG_IM_RES_OID);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_RES_VALUE))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_RES_VALUE = `enum LDAP_TAG_EXOP_RES_VALUE = ( cast( ber_tag_t ) 0x8bU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_RES_VALUE); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_RES_VALUE);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_RES_OID))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_RES_OID = `enum LDAP_TAG_EXOP_RES_OID = ( cast( ber_tag_t ) 0x8aU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_RES_OID); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_RES_OID);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_REQ_VALUE))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_REQ_VALUE = `enum LDAP_TAG_EXOP_REQ_VALUE = ( cast( ber_tag_t ) 0x81U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_REQ_VALUE); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_REQ_VALUE);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_REQ_OID))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_REQ_OID = `enum LDAP_TAG_EXOP_REQ_OID = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_REQ_OID); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_REQ_OID);
        }
    }




    static if(!is(typeof(LDAP_TAG_NEWSUPERIOR))) {
        private enum enumMixinStr_LDAP_TAG_NEWSUPERIOR = `enum LDAP_TAG_NEWSUPERIOR = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_NEWSUPERIOR); }))) {
            mixin(enumMixinStr_LDAP_TAG_NEWSUPERIOR);
        }
    }




    static if(!is(typeof(LDAP_TAG_REFERRAL))) {
        private enum enumMixinStr_LDAP_TAG_REFERRAL = `enum LDAP_TAG_REFERRAL = ( cast( ber_tag_t ) 0xa3U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_REFERRAL); }))) {
            mixin(enumMixinStr_LDAP_TAG_REFERRAL);
        }
    }




    static if(!is(typeof(LDAP_TAG_CONTROLS))) {
        private enum enumMixinStr_LDAP_TAG_CONTROLS = `enum LDAP_TAG_CONTROLS = ( cast( ber_tag_t ) 0xa0U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_CONTROLS); }))) {
            mixin(enumMixinStr_LDAP_TAG_CONTROLS);
        }
    }




    static if(!is(typeof(LDAP_TAG_LDAPCRED))) {
        private enum enumMixinStr_LDAP_TAG_LDAPCRED = `enum LDAP_TAG_LDAPCRED = ( cast( ber_tag_t ) 0x04U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_LDAPCRED); }))) {
            mixin(enumMixinStr_LDAP_TAG_LDAPCRED);
        }
    }




    static if(!is(typeof(LDAP_TAG_LDAPDN))) {
        private enum enumMixinStr_LDAP_TAG_LDAPDN = `enum LDAP_TAG_LDAPDN = ( cast( ber_tag_t ) 0x04U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_LDAPDN); }))) {
            mixin(enumMixinStr_LDAP_TAG_LDAPDN);
        }
    }




    static if(!is(typeof(LDAP_TAG_MSGID))) {
        private enum enumMixinStr_LDAP_TAG_MSGID = `enum LDAP_TAG_MSGID = ( cast( ber_tag_t ) 0x02U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_MSGID); }))) {
            mixin(enumMixinStr_LDAP_TAG_MSGID);
        }
    }




    static if(!is(typeof(LDAP_TAG_MESSAGE))) {
        private enum enumMixinStr_LDAP_TAG_MESSAGE = `enum LDAP_TAG_MESSAGE = ( cast( ber_tag_t ) 0x30U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_MESSAGE); }))) {
            mixin(enumMixinStr_LDAP_TAG_MESSAGE);
        }
    }




    static if(!is(typeof(LDAP_FEATURE_CHILDREN_SCOPE))) {
        private enum enumMixinStr_LDAP_FEATURE_CHILDREN_SCOPE = `enum LDAP_FEATURE_CHILDREN_SCOPE = LDAP_FEATURE_SUBORDINATE_SCOPE;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FEATURE_CHILDREN_SCOPE); }))) {
            mixin(enumMixinStr_LDAP_FEATURE_CHILDREN_SCOPE);
        }
    }




    static if(!is(typeof(LDAP_FEATURE_SUBORDINATE_SCOPE))) {
        private enum enumMixinStr_LDAP_FEATURE_SUBORDINATE_SCOPE = `enum LDAP_FEATURE_SUBORDINATE_SCOPE = "1.3.6.1.4.1.4203.666.8.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FEATURE_SUBORDINATE_SCOPE); }))) {
            mixin(enumMixinStr_LDAP_FEATURE_SUBORDINATE_SCOPE);
        }
    }




    static if(!is(typeof(LDAP_FEATURE_MODIFY_INCREMENT))) {
        private enum enumMixinStr_LDAP_FEATURE_MODIFY_INCREMENT = `enum LDAP_FEATURE_MODIFY_INCREMENT = "1.3.6.1.1.14";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FEATURE_MODIFY_INCREMENT); }))) {
            mixin(enumMixinStr_LDAP_FEATURE_MODIFY_INCREMENT);
        }
    }




    static if(!is(typeof(LDAP_FEATURE_LANGUAGE_RANGE_OPTIONS))) {
        private enum enumMixinStr_LDAP_FEATURE_LANGUAGE_RANGE_OPTIONS = `enum LDAP_FEATURE_LANGUAGE_RANGE_OPTIONS = "1.3.6.1.4.1.4203.1.5.5";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FEATURE_LANGUAGE_RANGE_OPTIONS); }))) {
            mixin(enumMixinStr_LDAP_FEATURE_LANGUAGE_RANGE_OPTIONS);
        }
    }




    static if(!is(typeof(LDAP_FEATURE_LANGUAGE_TAG_OPTIONS))) {
        private enum enumMixinStr_LDAP_FEATURE_LANGUAGE_TAG_OPTIONS = `enum LDAP_FEATURE_LANGUAGE_TAG_OPTIONS = "1.3.6.1.4.1.4203.1.5.4";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FEATURE_LANGUAGE_TAG_OPTIONS); }))) {
            mixin(enumMixinStr_LDAP_FEATURE_LANGUAGE_TAG_OPTIONS);
        }
    }




    static if(!is(typeof(LDAP_FEATURE_ABSOLUTE_FILTERS))) {
        private enum enumMixinStr_LDAP_FEATURE_ABSOLUTE_FILTERS = `enum LDAP_FEATURE_ABSOLUTE_FILTERS = "1.3.6.1.4.1.4203.1.5.3";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FEATURE_ABSOLUTE_FILTERS); }))) {
            mixin(enumMixinStr_LDAP_FEATURE_ABSOLUTE_FILTERS);
        }
    }




    static if(!is(typeof(LDAP_FEATURE_OBJECTCLASS_ATTRS))) {
        private enum enumMixinStr_LDAP_FEATURE_OBJECTCLASS_ATTRS = `enum LDAP_FEATURE_OBJECTCLASS_ATTRS = "1.3.6.1.4.1.4203.1.5.2";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FEATURE_OBJECTCLASS_ATTRS); }))) {
            mixin(enumMixinStr_LDAP_FEATURE_OBJECTCLASS_ATTRS);
        }
    }




    static if(!is(typeof(LDAP_FEATURE_ALL_OP_ATTRS))) {
        private enum enumMixinStr_LDAP_FEATURE_ALL_OP_ATTRS = `enum LDAP_FEATURE_ALL_OP_ATTRS = "1.3.6.1.4.1.4203.1.5.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FEATURE_ALL_OP_ATTRS); }))) {
            mixin(enumMixinStr_LDAP_FEATURE_ALL_OP_ATTRS);
        }
    }




    static if(!is(typeof(LDAP_URLEXT_X_FAILEDNAME))) {
        private enum enumMixinStr_LDAP_URLEXT_X_FAILEDNAME = `enum LDAP_URLEXT_X_FAILEDNAME = "x-failedName";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URLEXT_X_FAILEDNAME); }))) {
            mixin(enumMixinStr_LDAP_URLEXT_X_FAILEDNAME);
        }
    }




    static if(!is(typeof(LDAP_URLEXT_X_SEARCHEDSUBTREE))) {
        private enum enumMixinStr_LDAP_URLEXT_X_SEARCHEDSUBTREE = `enum LDAP_URLEXT_X_SEARCHEDSUBTREE = "x-searchedSubtree";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URLEXT_X_SEARCHEDSUBTREE); }))) {
            mixin(enumMixinStr_LDAP_URLEXT_X_SEARCHEDSUBTREE);
        }
    }




    static if(!is(typeof(LDAP_URLEXT_X_REFTYPE))) {
        private enum enumMixinStr_LDAP_URLEXT_X_REFTYPE = `enum LDAP_URLEXT_X_REFTYPE = "x-referenceType";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URLEXT_X_REFTYPE); }))) {
            mixin(enumMixinStr_LDAP_URLEXT_X_REFTYPE);
        }
    }




    static if(!is(typeof(LDAP_URLEXT_X_LOCALREF))) {
        private enum enumMixinStr_LDAP_URLEXT_X_LOCALREF = `enum LDAP_URLEXT_X_LOCALREF = "x-localReference";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URLEXT_X_LOCALREF); }))) {
            mixin(enumMixinStr_LDAP_URLEXT_X_LOCALREF);
        }
    }




    static if(!is(typeof(LDAP_URLEXT_X_FAILEDNAMEOID))) {
        private enum enumMixinStr_LDAP_URLEXT_X_FAILEDNAMEOID = `enum LDAP_URLEXT_X_FAILEDNAMEOID = LDAP_X_DISTPROC_BASE ".7";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URLEXT_X_FAILEDNAMEOID); }))) {
            mixin(enumMixinStr_LDAP_URLEXT_X_FAILEDNAMEOID);
        }
    }




    static if(!is(typeof(LDAP_URLEXT_X_SEARCHEDSUBTREEOID))) {
        private enum enumMixinStr_LDAP_URLEXT_X_SEARCHEDSUBTREEOID = `enum LDAP_URLEXT_X_SEARCHEDSUBTREEOID = LDAP_X_DISTPROC_BASE ".6";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URLEXT_X_SEARCHEDSUBTREEOID); }))) {
            mixin(enumMixinStr_LDAP_URLEXT_X_SEARCHEDSUBTREEOID);
        }
    }




    static if(!is(typeof(LDAP_URLEXT_X_REFTYPEOID))) {
        private enum enumMixinStr_LDAP_URLEXT_X_REFTYPEOID = `enum LDAP_URLEXT_X_REFTYPEOID = LDAP_X_DISTPROC_BASE ".5";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URLEXT_X_REFTYPEOID); }))) {
            mixin(enumMixinStr_LDAP_URLEXT_X_REFTYPEOID);
        }
    }




    static if(!is(typeof(LDAP_URLEXT_X_LOCALREFOID))) {
        private enum enumMixinStr_LDAP_URLEXT_X_LOCALREFOID = `enum LDAP_URLEXT_X_LOCALREFOID = LDAP_X_DISTPROC_BASE ".4";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_URLEXT_X_LOCALREFOID); }))) {
            mixin(enumMixinStr_LDAP_URLEXT_X_LOCALREFOID);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_RETURNCONTREF))) {
        private enum enumMixinStr_LDAP_CONTROL_X_RETURNCONTREF = `enum LDAP_CONTROL_X_RETURNCONTREF = LDAP_X_DISTPROC_BASE ".3";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_RETURNCONTREF); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_RETURNCONTREF);
        }
    }




    static if(!is(typeof(LDAP_FEATURE_X_CANCHAINOPS))) {
        private enum enumMixinStr_LDAP_FEATURE_X_CANCHAINOPS = `enum LDAP_FEATURE_X_CANCHAINOPS = LDAP_X_DISTPROC_BASE ".2";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FEATURE_X_CANCHAINOPS); }))) {
            mixin(enumMixinStr_LDAP_FEATURE_X_CANCHAINOPS);
        }
    }




    static if(!is(typeof(LDAP_EXOP_X_CHAINEDREQUEST))) {
        private enum enumMixinStr_LDAP_EXOP_X_CHAINEDREQUEST = `enum LDAP_EXOP_X_CHAINEDREQUEST = LDAP_X_DISTPROC_BASE ".1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_EXOP_X_CHAINEDREQUEST); }))) {
            mixin(enumMixinStr_LDAP_EXOP_X_CHAINEDREQUEST);
        }
    }




    static if(!is(typeof(LDAP_X_DISTPROC_BASE))) {
        private enum enumMixinStr_LDAP_X_DISTPROC_BASE = `enum LDAP_X_DISTPROC_BASE = "1.3.6.1.4.1.4203.666.11.6";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_X_DISTPROC_BASE); }))) {
            mixin(enumMixinStr_LDAP_X_DISTPROC_BASE);
        }
    }




    static if(!is(typeof(LDAP_EXOP_X_TURN))) {
        private enum enumMixinStr_LDAP_EXOP_X_TURN = `enum LDAP_EXOP_X_TURN = LDAP_EXOP_TURN;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_EXOP_X_TURN); }))) {
            mixin(enumMixinStr_LDAP_EXOP_X_TURN);
        }
    }




    static if(!is(typeof(LDAP_EXOP_TURN))) {
        private enum enumMixinStr_LDAP_EXOP_TURN = `enum LDAP_EXOP_TURN = "1.3.6.1.1.19";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_EXOP_TURN); }))) {
            mixin(enumMixinStr_LDAP_EXOP_TURN);
        }
    }




    static if(!is(typeof(LDAP_EXOP_X_WHO_AM_I))) {
        private enum enumMixinStr_LDAP_EXOP_X_WHO_AM_I = `enum LDAP_EXOP_X_WHO_AM_I = LDAP_EXOP_WHO_AM_I;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_EXOP_X_WHO_AM_I); }))) {
            mixin(enumMixinStr_LDAP_EXOP_X_WHO_AM_I);
        }
    }




    static if(!is(typeof(LDAP_EXOP_WHO_AM_I))) {
        private enum enumMixinStr_LDAP_EXOP_WHO_AM_I = `enum LDAP_EXOP_WHO_AM_I = "1.3.6.1.4.1.4203.1.11.3";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_EXOP_WHO_AM_I); }))) {
            mixin(enumMixinStr_LDAP_EXOP_WHO_AM_I);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_REFRESH_RES_TTL))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_REFRESH_RES_TTL = `enum LDAP_TAG_EXOP_REFRESH_RES_TTL = ( cast( ber_tag_t ) 0x81U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_REFRESH_RES_TTL); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_REFRESH_RES_TTL);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_REFRESH_REQ_TTL))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_REFRESH_REQ_TTL = `enum LDAP_TAG_EXOP_REFRESH_REQ_TTL = ( cast( ber_tag_t ) 0x81U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_REFRESH_REQ_TTL); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_REFRESH_REQ_TTL);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_REFRESH_REQ_DN))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_REFRESH_REQ_DN = `enum LDAP_TAG_EXOP_REFRESH_REQ_DN = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_REFRESH_REQ_DN); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_REFRESH_REQ_DN);
        }
    }




    static if(!is(typeof(LDAP_EXOP_REFRESH))) {
        private enum enumMixinStr_LDAP_EXOP_REFRESH = `enum LDAP_EXOP_REFRESH = "1.3.6.1.4.1.1466.101.119.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_EXOP_REFRESH); }))) {
            mixin(enumMixinStr_LDAP_EXOP_REFRESH);
        }
    }




    static if(!is(typeof(LDAP_EXOP_X_CANCEL))) {
        private enum enumMixinStr_LDAP_EXOP_X_CANCEL = `enum LDAP_EXOP_X_CANCEL = LDAP_EXOP_CANCEL;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_EXOP_X_CANCEL); }))) {
            mixin(enumMixinStr_LDAP_EXOP_X_CANCEL);
        }
    }




    static if(!is(typeof(LDAP_EXOP_CANCEL))) {
        private enum enumMixinStr_LDAP_EXOP_CANCEL = `enum LDAP_EXOP_CANCEL = "1.3.6.1.1.8";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_EXOP_CANCEL); }))) {
            mixin(enumMixinStr_LDAP_EXOP_CANCEL);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_MODIFY_PASSWD_GEN))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_GEN = `enum LDAP_TAG_EXOP_MODIFY_PASSWD_GEN = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_GEN); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_GEN);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_MODIFY_PASSWD_NEW))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_NEW = `enum LDAP_TAG_EXOP_MODIFY_PASSWD_NEW = ( cast( ber_tag_t ) 0x82U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_NEW); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_NEW);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_MODIFY_PASSWD_OLD))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_OLD = `enum LDAP_TAG_EXOP_MODIFY_PASSWD_OLD = ( cast( ber_tag_t ) 0x81U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_OLD); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_OLD);
        }
    }




    static if(!is(typeof(LDAP_TAG_EXOP_MODIFY_PASSWD_ID))) {
        private enum enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_ID = `enum LDAP_TAG_EXOP_MODIFY_PASSWD_ID = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_ID); }))) {
            mixin(enumMixinStr_LDAP_TAG_EXOP_MODIFY_PASSWD_ID);
        }
    }




    static if(!is(typeof(LDAP_EXOP_MODIFY_PASSWD))) {
        private enum enumMixinStr_LDAP_EXOP_MODIFY_PASSWD = `enum LDAP_EXOP_MODIFY_PASSWD = "1.3.6.1.4.1.4203.1.11.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_EXOP_MODIFY_PASSWD); }))) {
            mixin(enumMixinStr_LDAP_EXOP_MODIFY_PASSWD);
        }
    }




    static if(!is(typeof(LDAP_EXOP_START_TLS))) {
        private enum enumMixinStr_LDAP_EXOP_START_TLS = `enum LDAP_EXOP_START_TLS = "1.3.6.1.4.1.1466.20037";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_EXOP_START_TLS); }))) {
            mixin(enumMixinStr_LDAP_EXOP_START_TLS);
        }
    }




    static if(!is(typeof(LDAP_NOTICE_DISCONNECT))) {
        private enum enumMixinStr_LDAP_NOTICE_DISCONNECT = `enum LDAP_NOTICE_DISCONNECT = LDAP_NOTICE_OF_DISCONNECTION;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NOTICE_DISCONNECT); }))) {
            mixin(enumMixinStr_LDAP_NOTICE_DISCONNECT);
        }
    }




    static if(!is(typeof(LDAP_NOTICE_OF_DISCONNECTION))) {
        private enum enumMixinStr_LDAP_NOTICE_OF_DISCONNECTION = `enum LDAP_NOTICE_OF_DISCONNECTION = "1.3.6.1.4.1.1466.20036";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NOTICE_OF_DISCONNECTION); }))) {
            mixin(enumMixinStr_LDAP_NOTICE_OF_DISCONNECTION);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_VLVRESPONSE))) {
        private enum enumMixinStr_LDAP_CONTROL_VLVRESPONSE = `enum LDAP_CONTROL_VLVRESPONSE = "2.16.840.1.113730.3.4.10";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_VLVRESPONSE); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_VLVRESPONSE);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_VLVREQUEST))) {
        private enum enumMixinStr_LDAP_CONTROL_VLVREQUEST = `enum LDAP_CONTROL_VLVREQUEST = "2.16.840.1.113730.3.4.9";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_VLVREQUEST); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_VLVREQUEST);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PERSIST_ENTRY_CHANGE_RENAME))) {
        private enum enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_RENAME = `enum LDAP_CONTROL_PERSIST_ENTRY_CHANGE_RENAME = 0x8;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_RENAME); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_RENAME);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PERSIST_ENTRY_CHANGE_MODIFY))) {
        private enum enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_MODIFY = `enum LDAP_CONTROL_PERSIST_ENTRY_CHANGE_MODIFY = 0x4;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_MODIFY); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_MODIFY);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PERSIST_ENTRY_CHANGE_DELETE))) {
        private enum enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_DELETE = `enum LDAP_CONTROL_PERSIST_ENTRY_CHANGE_DELETE = 0x2;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_DELETE); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_DELETE);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PERSIST_ENTRY_CHANGE_ADD))) {
        private enum enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_ADD = `enum LDAP_CONTROL_PERSIST_ENTRY_CHANGE_ADD = 0x1;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_ADD); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_ADD);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PERSIST_ENTRY_CHANGE_NOTICE))) {
        private enum enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_NOTICE = `enum LDAP_CONTROL_PERSIST_ENTRY_CHANGE_NOTICE = "2.16.840.1.113730.3.4.7";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_NOTICE); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PERSIST_ENTRY_CHANGE_NOTICE);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PERSIST_REQUEST))) {
        private enum enumMixinStr_LDAP_CONTROL_PERSIST_REQUEST = `enum LDAP_CONTROL_PERSIST_REQUEST = "2.16.840.1.113730.3.4.3";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PERSIST_REQUEST); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PERSIST_REQUEST);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_DUPENT))) {
        private enum enumMixinStr_LDAP_CONTROL_DUPENT = `enum LDAP_CONTROL_DUPENT = LDAP_CONTROL_DUPENT_REQUEST;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_DUPENT); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_DUPENT);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_DUPENT_ENTRY))) {
        private enum enumMixinStr_LDAP_CONTROL_DUPENT_ENTRY = `enum LDAP_CONTROL_DUPENT_ENTRY = "2.16.840.1.113719.1.27.101.3";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_DUPENT_ENTRY); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_DUPENT_ENTRY);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_DUPENT_RESPONSE))) {
        private enum enumMixinStr_LDAP_CONTROL_DUPENT_RESPONSE = `enum LDAP_CONTROL_DUPENT_RESPONSE = "2.16.840.1.113719.1.27.101.2";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_DUPENT_RESPONSE); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_DUPENT_RESPONSE);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_DUPENT_REQUEST))) {
        private enum enumMixinStr_LDAP_CONTROL_DUPENT_REQUEST = `enum LDAP_CONTROL_DUPENT_REQUEST = "2.16.840.1.113719.1.27.101.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_DUPENT_REQUEST); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_DUPENT_REQUEST);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_SESSION_TRACKING_USERNAME))) {
        private enum enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING_USERNAME = `enum LDAP_CONTROL_X_SESSION_TRACKING_USERNAME = LDAP_CONTROL_X_SESSION_TRACKING ".3";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING_USERNAME); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING_USERNAME);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_MULTI_SESSION_ID))) {
        private enum enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_MULTI_SESSION_ID = `enum LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_MULTI_SESSION_ID = LDAP_CONTROL_X_SESSION_TRACKING ".2";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_MULTI_SESSION_ID); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_MULTI_SESSION_ID);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_SESSION_ID))) {
        private enum enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_SESSION_ID = `enum LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_SESSION_ID = LDAP_CONTROL_X_SESSION_TRACKING ".1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_SESSION_ID); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_SESSION_ID);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_SESSION_TRACKING))) {
        private enum enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING = `enum LDAP_CONTROL_X_SESSION_TRACKING = "1.3.6.1.4.1.21008.108.63.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_SESSION_TRACKING);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_EXTENDED_DN))) {
        private enum enumMixinStr_LDAP_CONTROL_X_EXTENDED_DN = `enum LDAP_CONTROL_X_EXTENDED_DN = "1.2.840.113556.1.4.529";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_EXTENDED_DN); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_EXTENDED_DN);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_TREE_DELETE))) {
        private enum enumMixinStr_LDAP_CONTROL_X_TREE_DELETE = `enum LDAP_CONTROL_X_TREE_DELETE = "1.2.840.113556.1.4.805";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_TREE_DELETE); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_TREE_DELETE);
        }
    }




    static if(!is(typeof(LDAP_SEARCH_FLAG_PHANTOM_ROOT))) {
        private enum enumMixinStr_LDAP_SEARCH_FLAG_PHANTOM_ROOT = `enum LDAP_SEARCH_FLAG_PHANTOM_ROOT = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SEARCH_FLAG_PHANTOM_ROOT); }))) {
            mixin(enumMixinStr_LDAP_SEARCH_FLAG_PHANTOM_ROOT);
        }
    }




    static if(!is(typeof(LDAP_SEARCH_FLAG_DOMAIN_SCOPE))) {
        private enum enumMixinStr_LDAP_SEARCH_FLAG_DOMAIN_SCOPE = `enum LDAP_SEARCH_FLAG_DOMAIN_SCOPE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SEARCH_FLAG_DOMAIN_SCOPE); }))) {
            mixin(enumMixinStr_LDAP_SEARCH_FLAG_DOMAIN_SCOPE);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_SEARCH_OPTIONS))) {
        private enum enumMixinStr_LDAP_CONTROL_X_SEARCH_OPTIONS = `enum LDAP_CONTROL_X_SEARCH_OPTIONS = "1.2.840.113556.1.4.1340";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_SEARCH_OPTIONS); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_SEARCH_OPTIONS);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_PERMISSIVE_MODIFY))) {
        private enum enumMixinStr_LDAP_CONTROL_X_PERMISSIVE_MODIFY = `enum LDAP_CONTROL_X_PERMISSIVE_MODIFY = "1.2.840.113556.1.4.1413";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_PERMISSIVE_MODIFY); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_PERMISSIVE_MODIFY);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_DOMAIN_SCOPE))) {
        private enum enumMixinStr_LDAP_CONTROL_X_DOMAIN_SCOPE = `enum LDAP_CONTROL_X_DOMAIN_SCOPE = "1.2.840.113556.1.4.1339";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_DOMAIN_SCOPE); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_DOMAIN_SCOPE);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_INCREMENTAL_VALUES))) {
        private enum enumMixinStr_LDAP_CONTROL_X_INCREMENTAL_VALUES = `enum LDAP_CONTROL_X_INCREMENTAL_VALUES = "1.2.840.113556.1.4.802";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_INCREMENTAL_VALUES); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_INCREMENTAL_VALUES);
        }
    }




    static if(!is(typeof(LDAP_REFERRALS_REQUIRED))) {
        private enum enumMixinStr_LDAP_REFERRALS_REQUIRED = `enum LDAP_REFERRALS_REQUIRED = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REFERRALS_REQUIRED); }))) {
            mixin(enumMixinStr_LDAP_REFERRALS_REQUIRED);
        }
    }




    static if(!is(typeof(LDAP_REFERRALS_PREFERRED))) {
        private enum enumMixinStr_LDAP_REFERRALS_PREFERRED = `enum LDAP_REFERRALS_PREFERRED = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_REFERRALS_PREFERRED); }))) {
            mixin(enumMixinStr_LDAP_REFERRALS_PREFERRED);
        }
    }




    static if(!is(typeof(LDAP_CHAINING_REQUIRED))) {
        private enum enumMixinStr_LDAP_CHAINING_REQUIRED = `enum LDAP_CHAINING_REQUIRED = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CHAINING_REQUIRED); }))) {
            mixin(enumMixinStr_LDAP_CHAINING_REQUIRED);
        }
    }




    static if(!is(typeof(LDAP_CHAINING_PREFERRED))) {
        private enum enumMixinStr_LDAP_CHAINING_PREFERRED = `enum LDAP_CHAINING_PREFERRED = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CHAINING_PREFERRED); }))) {
            mixin(enumMixinStr_LDAP_CHAINING_PREFERRED);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_CHAINING_BEHAVIOR))) {
        private enum enumMixinStr_LDAP_CONTROL_X_CHAINING_BEHAVIOR = `enum LDAP_CONTROL_X_CHAINING_BEHAVIOR = "1.3.6.1.4.1.4203.666.11.3";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_CHAINING_BEHAVIOR); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_CHAINING_BEHAVIOR);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_WHATFAILED))) {
        private enum enumMixinStr_LDAP_CONTROL_X_WHATFAILED = `enum LDAP_CONTROL_X_WHATFAILED = "1.3.6.1.4.1.4203.666.5.17";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_WHATFAILED); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_WHATFAILED);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_X_DEREF))) {
        private enum enumMixinStr_LDAP_CONTROL_X_DEREF = `enum LDAP_CONTROL_X_DEREF = "1.3.6.1.4.1.4203.666.5.16";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_X_DEREF); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_X_DEREF);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_VALSORT))) {
        private enum enumMixinStr_LDAP_CONTROL_VALSORT = `enum LDAP_CONTROL_VALSORT = "1.3.6.1.4.1.4203.666.5.14";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_VALSORT); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_VALSORT);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_SLURP))) {
        private enum enumMixinStr_LDAP_CONTROL_SLURP = `enum LDAP_CONTROL_SLURP = "1.3.6.1.4.1.4203.666.5.13";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_SLURP); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_SLURP);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_MANAGEDIT))) {
        private enum enumMixinStr_LDAP_CONTROL_MANAGEDIT = `enum LDAP_CONTROL_MANAGEDIT = LDAP_CONTROL_RELAX;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_MANAGEDIT); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_MANAGEDIT);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_RELAX))) {
        private enum enumMixinStr_LDAP_CONTROL_RELAX = `enum LDAP_CONTROL_RELAX = "1.3.6.1.4.1.4203.666.5.12";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_RELAX); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_RELAX);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_NO_SUBORDINATES))) {
        private enum enumMixinStr_LDAP_CONTROL_NO_SUBORDINATES = `enum LDAP_CONTROL_NO_SUBORDINATES = "1.3.6.1.4.1.4203.666.5.11";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_NO_SUBORDINATES); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_NO_SUBORDINATES);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_NOOP))) {
        private enum enumMixinStr_LDAP_CONTROL_NOOP = `enum LDAP_CONTROL_NOOP = "1.3.6.1.4.1.4203.666.5.2";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_NOOP); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_NOOP);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PASSWORDPOLICYRESPONSE))) {
        private enum enumMixinStr_LDAP_CONTROL_PASSWORDPOLICYRESPONSE = `enum LDAP_CONTROL_PASSWORDPOLICYRESPONSE = "1.3.6.1.4.1.42.2.27.8.5.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PASSWORDPOLICYRESPONSE); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PASSWORDPOLICYRESPONSE);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PASSWORDPOLICYREQUEST))) {
        private enum enumMixinStr_LDAP_CONTROL_PASSWORDPOLICYREQUEST = `enum LDAP_CONTROL_PASSWORDPOLICYREQUEST = "1.3.6.1.4.1.42.2.27.8.5.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PASSWORDPOLICYREQUEST); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PASSWORDPOLICYREQUEST);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_DONTUSECOPY))) {
        private enum enumMixinStr_LDAP_CONTROL_DONTUSECOPY = `enum LDAP_CONTROL_DONTUSECOPY = "1.3.6.1.1.22";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_DONTUSECOPY); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_DONTUSECOPY);
        }
    }




    static if(!is(typeof(LDAP_SYNC_NEW_COOKIE))) {
        private enum enumMixinStr_LDAP_SYNC_NEW_COOKIE = `enum LDAP_SYNC_NEW_COOKIE = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_NEW_COOKIE); }))) {
            mixin(enumMixinStr_LDAP_SYNC_NEW_COOKIE);
        }
    }




    static if(!is(typeof(LDAP_SYNC_DELETE))) {
        private enum enumMixinStr_LDAP_SYNC_DELETE = `enum LDAP_SYNC_DELETE = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_DELETE); }))) {
            mixin(enumMixinStr_LDAP_SYNC_DELETE);
        }
    }




    static if(!is(typeof(LDAP_SYNC_MODIFY))) {
        private enum enumMixinStr_LDAP_SYNC_MODIFY = `enum LDAP_SYNC_MODIFY = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_MODIFY); }))) {
            mixin(enumMixinStr_LDAP_SYNC_MODIFY);
        }
    }




    static if(!is(typeof(LDAP_SYNC_ADD))) {
        private enum enumMixinStr_LDAP_SYNC_ADD = `enum LDAP_SYNC_ADD = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_ADD); }))) {
            mixin(enumMixinStr_LDAP_SYNC_ADD);
        }
    }




    static if(!is(typeof(LDAP_AVA_NULL))) {
        private enum enumMixinStr_LDAP_AVA_NULL = `enum LDAP_AVA_NULL = 0x0000U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AVA_NULL); }))) {
            mixin(enumMixinStr_LDAP_AVA_NULL);
        }
    }




    static if(!is(typeof(LDAP_AVA_STRING))) {
        private enum enumMixinStr_LDAP_AVA_STRING = `enum LDAP_AVA_STRING = 0x0001U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AVA_STRING); }))) {
            mixin(enumMixinStr_LDAP_AVA_STRING);
        }
    }




    static if(!is(typeof(LDAP_AVA_BINARY))) {
        private enum enumMixinStr_LDAP_AVA_BINARY = `enum LDAP_AVA_BINARY = 0x0002U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AVA_BINARY); }))) {
            mixin(enumMixinStr_LDAP_AVA_BINARY);
        }
    }




    static if(!is(typeof(LDAP_AVA_NONPRINTABLE))) {
        private enum enumMixinStr_LDAP_AVA_NONPRINTABLE = `enum LDAP_AVA_NONPRINTABLE = 0x0004U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AVA_NONPRINTABLE); }))) {
            mixin(enumMixinStr_LDAP_AVA_NONPRINTABLE);
        }
    }




    static if(!is(typeof(LDAP_AVA_FREE_ATTR))) {
        private enum enumMixinStr_LDAP_AVA_FREE_ATTR = `enum LDAP_AVA_FREE_ATTR = 0x0010U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AVA_FREE_ATTR); }))) {
            mixin(enumMixinStr_LDAP_AVA_FREE_ATTR);
        }
    }




    static if(!is(typeof(LDAP_AVA_FREE_VALUE))) {
        private enum enumMixinStr_LDAP_AVA_FREE_VALUE = `enum LDAP_AVA_FREE_VALUE = 0x0020U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AVA_FREE_VALUE); }))) {
            mixin(enumMixinStr_LDAP_AVA_FREE_VALUE);
        }
    }




    static if(!is(typeof(LDAP_SYNC_PRESENT))) {
        private enum enumMixinStr_LDAP_SYNC_PRESENT = `enum LDAP_SYNC_PRESENT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_PRESENT); }))) {
            mixin(enumMixinStr_LDAP_SYNC_PRESENT);
        }
    }




    static if(!is(typeof(LDAP_TAG_RELOAD_HINT))) {
        private enum enumMixinStr_LDAP_TAG_RELOAD_HINT = `enum LDAP_TAG_RELOAD_HINT = ( cast( ber_tag_t ) 0x01U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_RELOAD_HINT); }))) {
            mixin(enumMixinStr_LDAP_TAG_RELOAD_HINT);
        }
    }




    static if(!is(typeof(LDAP_DN_FORMAT_LDAP))) {
        private enum enumMixinStr_LDAP_DN_FORMAT_LDAP = `enum LDAP_DN_FORMAT_LDAP = 0x0000U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_FORMAT_LDAP); }))) {
            mixin(enumMixinStr_LDAP_DN_FORMAT_LDAP);
        }
    }




    static if(!is(typeof(LDAP_DN_FORMAT_LDAPV3))) {
        private enum enumMixinStr_LDAP_DN_FORMAT_LDAPV3 = `enum LDAP_DN_FORMAT_LDAPV3 = 0x0010U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_FORMAT_LDAPV3); }))) {
            mixin(enumMixinStr_LDAP_DN_FORMAT_LDAPV3);
        }
    }




    static if(!is(typeof(LDAP_DN_FORMAT_LDAPV2))) {
        private enum enumMixinStr_LDAP_DN_FORMAT_LDAPV2 = `enum LDAP_DN_FORMAT_LDAPV2 = 0x0020U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_FORMAT_LDAPV2); }))) {
            mixin(enumMixinStr_LDAP_DN_FORMAT_LDAPV2);
        }
    }




    static if(!is(typeof(LDAP_DN_FORMAT_DCE))) {
        private enum enumMixinStr_LDAP_DN_FORMAT_DCE = `enum LDAP_DN_FORMAT_DCE = 0x0030U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_FORMAT_DCE); }))) {
            mixin(enumMixinStr_LDAP_DN_FORMAT_DCE);
        }
    }




    static if(!is(typeof(LDAP_DN_FORMAT_UFN))) {
        private enum enumMixinStr_LDAP_DN_FORMAT_UFN = `enum LDAP_DN_FORMAT_UFN = 0x0040U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_FORMAT_UFN); }))) {
            mixin(enumMixinStr_LDAP_DN_FORMAT_UFN);
        }
    }




    static if(!is(typeof(LDAP_DN_FORMAT_AD_CANONICAL))) {
        private enum enumMixinStr_LDAP_DN_FORMAT_AD_CANONICAL = `enum LDAP_DN_FORMAT_AD_CANONICAL = 0x0050U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_FORMAT_AD_CANONICAL); }))) {
            mixin(enumMixinStr_LDAP_DN_FORMAT_AD_CANONICAL);
        }
    }




    static if(!is(typeof(LDAP_DN_FORMAT_LBER))) {
        private enum enumMixinStr_LDAP_DN_FORMAT_LBER = `enum LDAP_DN_FORMAT_LBER = 0x00F0U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_FORMAT_LBER); }))) {
            mixin(enumMixinStr_LDAP_DN_FORMAT_LBER);
        }
    }




    static if(!is(typeof(LDAP_DN_FORMAT_MASK))) {
        private enum enumMixinStr_LDAP_DN_FORMAT_MASK = `enum LDAP_DN_FORMAT_MASK = 0x00F0U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_FORMAT_MASK); }))) {
            mixin(enumMixinStr_LDAP_DN_FORMAT_MASK);
        }
    }




    static if(!is(typeof(LDAP_DN_PRETTY))) {
        private enum enumMixinStr_LDAP_DN_PRETTY = `enum LDAP_DN_PRETTY = 0x0100U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_PRETTY); }))) {
            mixin(enumMixinStr_LDAP_DN_PRETTY);
        }
    }




    static if(!is(typeof(LDAP_DN_SKIP))) {
        private enum enumMixinStr_LDAP_DN_SKIP = `enum LDAP_DN_SKIP = 0x0200U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_SKIP); }))) {
            mixin(enumMixinStr_LDAP_DN_SKIP);
        }
    }




    static if(!is(typeof(LDAP_DN_P_NOLEADTRAILSPACES))) {
        private enum enumMixinStr_LDAP_DN_P_NOLEADTRAILSPACES = `enum LDAP_DN_P_NOLEADTRAILSPACES = 0x1000U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_P_NOLEADTRAILSPACES); }))) {
            mixin(enumMixinStr_LDAP_DN_P_NOLEADTRAILSPACES);
        }
    }




    static if(!is(typeof(LDAP_DN_P_NOSPACEAFTERRDN))) {
        private enum enumMixinStr_LDAP_DN_P_NOSPACEAFTERRDN = `enum LDAP_DN_P_NOSPACEAFTERRDN = 0x2000U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_P_NOSPACEAFTERRDN); }))) {
            mixin(enumMixinStr_LDAP_DN_P_NOSPACEAFTERRDN);
        }
    }




    static if(!is(typeof(LDAP_DN_PEDANTIC))) {
        private enum enumMixinStr_LDAP_DN_PEDANTIC = `enum LDAP_DN_PEDANTIC = 0xF000U;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_DN_PEDANTIC); }))) {
            mixin(enumMixinStr_LDAP_DN_PEDANTIC);
        }
    }




    static if(!is(typeof(LDAP_TAG_REFRESHDONE))) {
        private enum enumMixinStr_LDAP_TAG_REFRESHDONE = `enum LDAP_TAG_REFRESHDONE = ( cast( ber_tag_t ) 0x01U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_REFRESHDONE); }))) {
            mixin(enumMixinStr_LDAP_TAG_REFRESHDONE);
        }
    }




    static if(!is(typeof(LDAP_TAG_REFRESHDELETES))) {
        private enum enumMixinStr_LDAP_TAG_REFRESHDELETES = `enum LDAP_TAG_REFRESHDELETES = ( cast( ber_tag_t ) 0x01U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_REFRESHDELETES); }))) {
            mixin(enumMixinStr_LDAP_TAG_REFRESHDELETES);
        }
    }




    static if(!is(typeof(LDAP_TAG_SYNC_COOKIE))) {
        private enum enumMixinStr_LDAP_TAG_SYNC_COOKIE = `enum LDAP_TAG_SYNC_COOKIE = ( cast( ber_tag_t ) 0x04U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_SYNC_COOKIE); }))) {
            mixin(enumMixinStr_LDAP_TAG_SYNC_COOKIE);
        }
    }




    static if(!is(typeof(LDAP_TAG_SYNC_ID_SET))) {
        private enum enumMixinStr_LDAP_TAG_SYNC_ID_SET = `enum LDAP_TAG_SYNC_ID_SET = ( cast( ber_tag_t ) 0xa3U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_SYNC_ID_SET); }))) {
            mixin(enumMixinStr_LDAP_TAG_SYNC_ID_SET);
        }
    }




    static if(!is(typeof(LDAP_TAG_SYNC_REFRESH_PRESENT))) {
        private enum enumMixinStr_LDAP_TAG_SYNC_REFRESH_PRESENT = `enum LDAP_TAG_SYNC_REFRESH_PRESENT = ( cast( ber_tag_t ) 0xa2U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_SYNC_REFRESH_PRESENT); }))) {
            mixin(enumMixinStr_LDAP_TAG_SYNC_REFRESH_PRESENT);
        }
    }




    static if(!is(typeof(LDAP_TAG_SYNC_REFRESH_DELETE))) {
        private enum enumMixinStr_LDAP_TAG_SYNC_REFRESH_DELETE = `enum LDAP_TAG_SYNC_REFRESH_DELETE = ( cast( ber_tag_t ) 0xa1U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_SYNC_REFRESH_DELETE); }))) {
            mixin(enumMixinStr_LDAP_TAG_SYNC_REFRESH_DELETE);
        }
    }




    static if(!is(typeof(LDAP_TAG_SYNC_NEW_COOKIE))) {
        private enum enumMixinStr_LDAP_TAG_SYNC_NEW_COOKIE = `enum LDAP_TAG_SYNC_NEW_COOKIE = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_TAG_SYNC_NEW_COOKIE); }))) {
            mixin(enumMixinStr_LDAP_TAG_SYNC_NEW_COOKIE);
        }
    }




    static if(!is(typeof(LDAP_SYNC_REFRESH_DELETES))) {
        private enum enumMixinStr_LDAP_SYNC_REFRESH_DELETES = `enum LDAP_SYNC_REFRESH_DELETES = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_REFRESH_DELETES); }))) {
            mixin(enumMixinStr_LDAP_SYNC_REFRESH_DELETES);
        }
    }




    static if(!is(typeof(LDAP_SYNC_REFRESH_PRESENTS))) {
        private enum enumMixinStr_LDAP_SYNC_REFRESH_PRESENTS = `enum LDAP_SYNC_REFRESH_PRESENTS = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_REFRESH_PRESENTS); }))) {
            mixin(enumMixinStr_LDAP_SYNC_REFRESH_PRESENTS);
        }
    }




    static if(!is(typeof(LDAP_SYNC_REFRESH_AND_PERSIST))) {
        private enum enumMixinStr_LDAP_SYNC_REFRESH_AND_PERSIST = `enum LDAP_SYNC_REFRESH_AND_PERSIST = 0x03;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_REFRESH_AND_PERSIST); }))) {
            mixin(enumMixinStr_LDAP_SYNC_REFRESH_AND_PERSIST);
        }
    }




    static if(!is(typeof(LDAP_SYNC_RESERVED))) {
        private enum enumMixinStr_LDAP_SYNC_RESERVED = `enum LDAP_SYNC_RESERVED = 0x02;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_RESERVED); }))) {
            mixin(enumMixinStr_LDAP_SYNC_RESERVED);
        }
    }




    static if(!is(typeof(LDAP_SYNC_REFRESH_ONLY))) {
        private enum enumMixinStr_LDAP_SYNC_REFRESH_ONLY = `enum LDAP_SYNC_REFRESH_ONLY = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_REFRESH_ONLY); }))) {
            mixin(enumMixinStr_LDAP_SYNC_REFRESH_ONLY);
        }
    }




    static if(!is(typeof(LDAP_SYNC_NONE))) {
        private enum enumMixinStr_LDAP_SYNC_NONE = `enum LDAP_SYNC_NONE = 0x00;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_NONE); }))) {
            mixin(enumMixinStr_LDAP_SYNC_NONE);
        }
    }




    static if(!is(typeof(LDAP_SYNC_INFO))) {
        private enum enumMixinStr_LDAP_SYNC_INFO = `enum LDAP_SYNC_INFO = LDAP_SYNC_OID ".4";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_INFO); }))) {
            mixin(enumMixinStr_LDAP_SYNC_INFO);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_SYNC_DONE))) {
        private enum enumMixinStr_LDAP_CONTROL_SYNC_DONE = `enum LDAP_CONTROL_SYNC_DONE = LDAP_SYNC_OID ".3";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_SYNC_DONE); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_SYNC_DONE);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_SYNC_STATE))) {
        private enum enumMixinStr_LDAP_CONTROL_SYNC_STATE = `enum LDAP_CONTROL_SYNC_STATE = LDAP_SYNC_OID ".2";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_SYNC_STATE); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_SYNC_STATE);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_SYNC))) {
        private enum enumMixinStr_LDAP_CONTROL_SYNC = `enum LDAP_CONTROL_SYNC = LDAP_SYNC_OID ".1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_SYNC); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_SYNC);
        }
    }




    static if(!is(typeof(LDAP_SYNC_OID))) {
        private enum enumMixinStr_LDAP_SYNC_OID = `enum LDAP_SYNC_OID = "1.3.6.1.4.1.4203.1.9.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_SYNC_OID); }))) {
            mixin(enumMixinStr_LDAP_SYNC_OID);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PAGEDRESULTS))) {
        private enum enumMixinStr_LDAP_CONTROL_PAGEDRESULTS = `enum LDAP_CONTROL_PAGEDRESULTS = "1.2.840.113556.1.4.319";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PAGEDRESULTS); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PAGEDRESULTS);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_SORTRESPONSE))) {
        private enum enumMixinStr_LDAP_CONTROL_SORTRESPONSE = `enum LDAP_CONTROL_SORTRESPONSE = "1.2.840.113556.1.4.474";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_SORTRESPONSE); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_SORTRESPONSE);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_SORTREQUEST))) {
        private enum enumMixinStr_LDAP_CONTROL_SORTREQUEST = `enum LDAP_CONTROL_SORTREQUEST = "1.2.840.113556.1.4.473";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_SORTREQUEST); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_SORTREQUEST);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_POST_READ))) {
        private enum enumMixinStr_LDAP_CONTROL_POST_READ = `enum LDAP_CONTROL_POST_READ = "1.3.6.1.1.13.2";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_POST_READ); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_POST_READ);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PRE_READ))) {
        private enum enumMixinStr_LDAP_CONTROL_PRE_READ = `enum LDAP_CONTROL_PRE_READ = "1.3.6.1.1.13.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PRE_READ); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PRE_READ);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_ASSERT))) {
        private enum enumMixinStr_LDAP_CONTROL_ASSERT = `enum LDAP_CONTROL_ASSERT = "1.3.6.1.1.12";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_ASSERT); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_ASSERT);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_VALUESRETURNFILTER))) {
        private enum enumMixinStr_LDAP_CONTROL_VALUESRETURNFILTER = `enum LDAP_CONTROL_VALUESRETURNFILTER = "1.2.826.0.1.3344810.2.3";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_VALUESRETURNFILTER); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_VALUESRETURNFILTER);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_SUBENTRIES))) {
        private enum enumMixinStr_LDAP_CONTROL_SUBENTRIES = `enum LDAP_CONTROL_SUBENTRIES = "1.3.6.1.4.1.4203.1.10.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_SUBENTRIES); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_SUBENTRIES);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_PROXY_AUTHZ))) {
        private enum enumMixinStr_LDAP_CONTROL_PROXY_AUTHZ = `enum LDAP_CONTROL_PROXY_AUTHZ = "2.16.840.1.113730.3.4.18";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_PROXY_AUTHZ); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_PROXY_AUTHZ);
        }
    }




    static if(!is(typeof(LDAP_CONTROL_MANAGEDSAIT))) {
        private enum enumMixinStr_LDAP_CONTROL_MANAGEDSAIT = `enum LDAP_CONTROL_MANAGEDSAIT = "2.16.840.1.113730.3.4.2";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONTROL_MANAGEDSAIT); }))) {
            mixin(enumMixinStr_LDAP_CONTROL_MANAGEDSAIT);
        }
    }




    static if(!is(typeof(LDAP_FEATURE_INFO_VERSION))) {
        private enum enumMixinStr_LDAP_FEATURE_INFO_VERSION = `enum LDAP_FEATURE_INFO_VERSION = ( 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_FEATURE_INFO_VERSION); }))) {
            mixin(enumMixinStr_LDAP_FEATURE_INFO_VERSION);
        }
    }




    static if(!is(typeof(LDAP_API_INFO_VERSION))) {
        private enum enumMixinStr_LDAP_API_INFO_VERSION = `enum LDAP_API_INFO_VERSION = ( 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_INFO_VERSION); }))) {
            mixin(enumMixinStr_LDAP_API_INFO_VERSION);
        }
    }




    static if(!is(typeof(LDAP_OPT_OFF))) {
        private enum enumMixinStr_LDAP_OPT_OFF = `enum LDAP_OPT_OFF = ( cast( void * ) 0 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_OFF); }))) {
            mixin(enumMixinStr_LDAP_OPT_OFF);
        }
    }




    static if(!is(typeof(LDAP_OPT_ON))) {
        private enum enumMixinStr_LDAP_OPT_ON = `enum LDAP_OPT_ON = ( cast( void * ) & ber_pvt_opt_on );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_ON); }))) {
            mixin(enumMixinStr_LDAP_OPT_ON);
        }
    }




    static if(!is(typeof(LDAP_OPT_ERROR))) {
        private enum enumMixinStr_LDAP_OPT_ERROR = `enum LDAP_OPT_ERROR = ( - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_ERROR); }))) {
            mixin(enumMixinStr_LDAP_OPT_ERROR);
        }
    }




    static if(!is(typeof(LDAP_OPT_SUCCESS))) {
        private enum enumMixinStr_LDAP_OPT_SUCCESS = `enum LDAP_OPT_SUCCESS = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_SUCCESS); }))) {
            mixin(enumMixinStr_LDAP_OPT_SUCCESS);
        }
    }




    static if(!is(typeof(LDAP_OPT_PRIVATE_EXTENSION_BASE))) {
        private enum enumMixinStr_LDAP_OPT_PRIVATE_EXTENSION_BASE = `enum LDAP_OPT_PRIVATE_EXTENSION_BASE = 0x7000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_PRIVATE_EXTENSION_BASE); }))) {
            mixin(enumMixinStr_LDAP_OPT_PRIVATE_EXTENSION_BASE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_KEEPALIVE_INTERVAL))) {
        private enum enumMixinStr_LDAP_OPT_X_KEEPALIVE_INTERVAL = `enum LDAP_OPT_X_KEEPALIVE_INTERVAL = 0x6302;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_KEEPALIVE_INTERVAL); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_KEEPALIVE_INTERVAL);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_KEEPALIVE_PROBES))) {
        private enum enumMixinStr_LDAP_OPT_X_KEEPALIVE_PROBES = `enum LDAP_OPT_X_KEEPALIVE_PROBES = 0x6301;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_KEEPALIVE_PROBES); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_KEEPALIVE_PROBES);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_KEEPALIVE_IDLE))) {
        private enum enumMixinStr_LDAP_OPT_X_KEEPALIVE_IDLE = `enum LDAP_OPT_X_KEEPALIVE_IDLE = 0x6300;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_KEEPALIVE_IDLE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_KEEPALIVE_IDLE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_GSSAPI_ALLOW_REMOTE_PRINCIPAL))) {
        private enum enumMixinStr_LDAP_OPT_X_GSSAPI_ALLOW_REMOTE_PRINCIPAL = `enum LDAP_OPT_X_GSSAPI_ALLOW_REMOTE_PRINCIPAL = 0x6201;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_GSSAPI_ALLOW_REMOTE_PRINCIPAL); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_GSSAPI_ALLOW_REMOTE_PRINCIPAL);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_GSSAPI_DO_NOT_FREE_CONTEXT))) {
        private enum enumMixinStr_LDAP_OPT_X_GSSAPI_DO_NOT_FREE_CONTEXT = `enum LDAP_OPT_X_GSSAPI_DO_NOT_FREE_CONTEXT = 0x6200;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_GSSAPI_DO_NOT_FREE_CONTEXT); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_GSSAPI_DO_NOT_FREE_CONTEXT);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_GSS_CREDS))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_GSS_CREDS = `enum LDAP_OPT_X_SASL_GSS_CREDS = 0x610d;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_GSS_CREDS); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_GSS_CREDS);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_USERNAME))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_USERNAME = `enum LDAP_OPT_X_SASL_USERNAME = 0x610c;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_USERNAME); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_USERNAME);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_NOCANON))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_NOCANON = `enum LDAP_OPT_X_SASL_NOCANON = 0x610b;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_NOCANON); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_NOCANON);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_MECHLIST))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_MECHLIST = `enum LDAP_OPT_X_SASL_MECHLIST = 0x610a;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_MECHLIST); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_MECHLIST);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_MAXBUFSIZE))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_MAXBUFSIZE = `enum LDAP_OPT_X_SASL_MAXBUFSIZE = 0x6109;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_MAXBUFSIZE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_MAXBUFSIZE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_SSF_MAX))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_SSF_MAX = `enum LDAP_OPT_X_SASL_SSF_MAX = 0x6108;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_SSF_MAX); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_SSF_MAX);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_SSF_MIN))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_SSF_MIN = `enum LDAP_OPT_X_SASL_SSF_MIN = 0x6107;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_SSF_MIN); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_SSF_MIN);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_SECPROPS))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_SECPROPS = `enum LDAP_OPT_X_SASL_SECPROPS = 0x6106;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_SECPROPS); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_SECPROPS);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_SSF_EXTERNAL))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_SSF_EXTERNAL = `enum LDAP_OPT_X_SASL_SSF_EXTERNAL = 0x6105;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_SSF_EXTERNAL); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_SSF_EXTERNAL);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_SSF))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_SSF = `enum LDAP_OPT_X_SASL_SSF = 0x6104;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_SSF); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_SSF);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_AUTHZID))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_AUTHZID = `enum LDAP_OPT_X_SASL_AUTHZID = 0x6103;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_AUTHZID); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_AUTHZID);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_AUTHCID))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_AUTHCID = `enum LDAP_OPT_X_SASL_AUTHCID = 0x6102;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_AUTHCID); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_AUTHCID);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_REALM))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_REALM = `enum LDAP_OPT_X_SASL_REALM = 0x6101;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_REALM); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_REALM);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_SASL_MECH))) {
        private enum enumMixinStr_LDAP_OPT_X_SASL_MECH = `enum LDAP_OPT_X_SASL_MECH = 0x6100;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_SASL_MECH); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_SASL_MECH);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_PROTOCOL_TLS1_2))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_TLS1_2 = `enum LDAP_OPT_X_TLS_PROTOCOL_TLS1_2 = ( ( 3 << 8 ) + 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_TLS1_2); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_TLS1_2);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_PROTOCOL_TLS1_1))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_TLS1_1 = `enum LDAP_OPT_X_TLS_PROTOCOL_TLS1_1 = ( ( 3 << 8 ) + 2 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_TLS1_1); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_TLS1_1);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_PROTOCOL_TLS1_0))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_TLS1_0 = `enum LDAP_OPT_X_TLS_PROTOCOL_TLS1_0 = ( ( 3 << 8 ) + 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_TLS1_0); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_TLS1_0);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_PROTOCOL_SSL3))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_SSL3 = `enum LDAP_OPT_X_TLS_PROTOCOL_SSL3 = ( 3 << 8 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_SSL3); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_SSL3);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_PROTOCOL_SSL2))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_SSL2 = `enum LDAP_OPT_X_TLS_PROTOCOL_SSL2 = ( 2 << 8 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_SSL2); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_SSL2);
        }
    }






    static if(!is(typeof(LDAP_OPT_X_TLS_CRL_ALL))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CRL_ALL = `enum LDAP_OPT_X_TLS_CRL_ALL = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CRL_ALL); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CRL_ALL);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CRL_PEER))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CRL_PEER = `enum LDAP_OPT_X_TLS_CRL_PEER = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CRL_PEER); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CRL_PEER);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CRL_NONE))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CRL_NONE = `enum LDAP_OPT_X_TLS_CRL_NONE = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CRL_NONE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CRL_NONE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_TRY))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_TRY = `enum LDAP_OPT_X_TLS_TRY = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_TRY); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_TRY);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_ALLOW))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_ALLOW = `enum LDAP_OPT_X_TLS_ALLOW = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_ALLOW); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_ALLOW);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_DEMAND))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_DEMAND = `enum LDAP_OPT_X_TLS_DEMAND = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_DEMAND); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_DEMAND);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_HARD))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_HARD = `enum LDAP_OPT_X_TLS_HARD = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_HARD); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_HARD);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_NEVER))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_NEVER = `enum LDAP_OPT_X_TLS_NEVER = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_NEVER); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_NEVER);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_ECNAME))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_ECNAME = `enum LDAP_OPT_X_TLS_ECNAME = 0x6012;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_ECNAME); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_ECNAME);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_PACKAGE))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_PACKAGE = `enum LDAP_OPT_X_TLS_PACKAGE = 0x6011;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_PACKAGE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_PACKAGE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CRLFILE))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CRLFILE = `enum LDAP_OPT_X_TLS_CRLFILE = 0x6010;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CRLFILE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CRLFILE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_NEWCTX))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_NEWCTX = `enum LDAP_OPT_X_TLS_NEWCTX = 0x600f;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_NEWCTX); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_NEWCTX);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_DHFILE))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_DHFILE = `enum LDAP_OPT_X_TLS_DHFILE = 0x600e;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_DHFILE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_DHFILE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CONNECT_ARG))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CONNECT_ARG = `enum LDAP_OPT_X_TLS_CONNECT_ARG = 0x600d;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CONNECT_ARG); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CONNECT_ARG);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CONNECT_CB))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CONNECT_CB = `enum LDAP_OPT_X_TLS_CONNECT_CB = 0x600c;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CONNECT_CB); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CONNECT_CB);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CRLCHECK))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CRLCHECK = `enum LDAP_OPT_X_TLS_CRLCHECK = 0x600b;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CRLCHECK); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CRLCHECK);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_SSL_CTX))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_SSL_CTX = `enum LDAP_OPT_X_TLS_SSL_CTX = 0x600a;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_SSL_CTX); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_SSL_CTX);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_RANDOM_FILE))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_RANDOM_FILE = `enum LDAP_OPT_X_TLS_RANDOM_FILE = 0x6009;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_RANDOM_FILE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_RANDOM_FILE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CIPHER_SUITE))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CIPHER_SUITE = `enum LDAP_OPT_X_TLS_CIPHER_SUITE = 0x6008;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CIPHER_SUITE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CIPHER_SUITE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_PROTOCOL_MIN))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_MIN = `enum LDAP_OPT_X_TLS_PROTOCOL_MIN = 0x6007;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_MIN); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_PROTOCOL_MIN);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_REQUIRE_CERT))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_REQUIRE_CERT = `enum LDAP_OPT_X_TLS_REQUIRE_CERT = 0x6006;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_REQUIRE_CERT); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_REQUIRE_CERT);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_KEYFILE))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_KEYFILE = `enum LDAP_OPT_X_TLS_KEYFILE = 0x6005;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_KEYFILE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_KEYFILE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CERTFILE))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CERTFILE = `enum LDAP_OPT_X_TLS_CERTFILE = 0x6004;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CERTFILE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CERTFILE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CACERTDIR))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CACERTDIR = `enum LDAP_OPT_X_TLS_CACERTDIR = 0x6003;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CACERTDIR); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CACERTDIR);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CACERTFILE))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CACERTFILE = `enum LDAP_OPT_X_TLS_CACERTFILE = 0x6002;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CACERTFILE); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CACERTFILE);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS_CTX))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS_CTX = `enum LDAP_OPT_X_TLS_CTX = 0x6001;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS_CTX); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS_CTX);
        }
    }




    static if(!is(typeof(LDAP_OPT_X_TLS))) {
        private enum enumMixinStr_LDAP_OPT_X_TLS = `enum LDAP_OPT_X_TLS = 0x6000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_X_TLS); }))) {
            mixin(enumMixinStr_LDAP_OPT_X_TLS);
        }
    }




    static if(!is(typeof(LDAP_OPT_SESSION_REFCNT))) {
        private enum enumMixinStr_LDAP_OPT_SESSION_REFCNT = `enum LDAP_OPT_SESSION_REFCNT = 0x5012;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_SESSION_REFCNT); }))) {
            mixin(enumMixinStr_LDAP_OPT_SESSION_REFCNT);
        }
    }




    static if(!is(typeof(LDAP_OPT_CONNECT_CB))) {
        private enum enumMixinStr_LDAP_OPT_CONNECT_CB = `enum LDAP_OPT_CONNECT_CB = 0x5011;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_CONNECT_CB); }))) {
            mixin(enumMixinStr_LDAP_OPT_CONNECT_CB);
        }
    }




    static if(!is(typeof(LDAP_OPT_CONNECT_ASYNC))) {
        private enum enumMixinStr_LDAP_OPT_CONNECT_ASYNC = `enum LDAP_OPT_CONNECT_ASYNC = 0x5010;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_CONNECT_ASYNC); }))) {
            mixin(enumMixinStr_LDAP_OPT_CONNECT_ASYNC);
        }
    }




    static if(!is(typeof(LDAP_OPT_DEFBASE))) {
        private enum enumMixinStr_LDAP_OPT_DEFBASE = `enum LDAP_OPT_DEFBASE = 0x5009;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_DEFBASE); }))) {
            mixin(enumMixinStr_LDAP_OPT_DEFBASE);
        }
    }




    static if(!is(typeof(LDAP_OPT_SOCKBUF))) {
        private enum enumMixinStr_LDAP_OPT_SOCKBUF = `enum LDAP_OPT_SOCKBUF = 0x5008;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_SOCKBUF); }))) {
            mixin(enumMixinStr_LDAP_OPT_SOCKBUF);
        }
    }




    static if(!is(typeof(LDAP_OPT_REFERRAL_URLS))) {
        private enum enumMixinStr_LDAP_OPT_REFERRAL_URLS = `enum LDAP_OPT_REFERRAL_URLS = 0x5007;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_REFERRAL_URLS); }))) {
            mixin(enumMixinStr_LDAP_OPT_REFERRAL_URLS);
        }
    }




    static if(!is(typeof(LDAP_OPT_URI))) {
        private enum enumMixinStr_LDAP_OPT_URI = `enum LDAP_OPT_URI = 0x5006;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_URI); }))) {
            mixin(enumMixinStr_LDAP_OPT_URI);
        }
    }




    static if(!is(typeof(LDAP_OPT_NETWORK_TIMEOUT))) {
        private enum enumMixinStr_LDAP_OPT_NETWORK_TIMEOUT = `enum LDAP_OPT_NETWORK_TIMEOUT = 0x5005;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_NETWORK_TIMEOUT); }))) {
            mixin(enumMixinStr_LDAP_OPT_NETWORK_TIMEOUT);
        }
    }




    static if(!is(typeof(LDAP_OPT_REFHOPLIMIT))) {
        private enum enumMixinStr_LDAP_OPT_REFHOPLIMIT = `enum LDAP_OPT_REFHOPLIMIT = 0x5003;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_REFHOPLIMIT); }))) {
            mixin(enumMixinStr_LDAP_OPT_REFHOPLIMIT);
        }
    }




    static if(!is(typeof(LDAP_OPT_TIMEOUT))) {
        private enum enumMixinStr_LDAP_OPT_TIMEOUT = `enum LDAP_OPT_TIMEOUT = 0x5002;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_TIMEOUT); }))) {
            mixin(enumMixinStr_LDAP_OPT_TIMEOUT);
        }
    }




    static if(!is(typeof(LDAP_OPT_DEBUG_LEVEL))) {
        private enum enumMixinStr_LDAP_OPT_DEBUG_LEVEL = `enum LDAP_OPT_DEBUG_LEVEL = 0x5001;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_DEBUG_LEVEL); }))) {
            mixin(enumMixinStr_LDAP_OPT_DEBUG_LEVEL);
        }
    }




    static if(!is(typeof(LDAP_OPT_API_EXTENSION_BASE))) {
        private enum enumMixinStr_LDAP_OPT_API_EXTENSION_BASE = `enum LDAP_OPT_API_EXTENSION_BASE = 0x4000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_API_EXTENSION_BASE); }))) {
            mixin(enumMixinStr_LDAP_OPT_API_EXTENSION_BASE);
        }
    }




    static if(!is(typeof(LDAP_OPT_SECURITY_CONTEXT))) {
        private enum enumMixinStr_LDAP_OPT_SECURITY_CONTEXT = `enum LDAP_OPT_SECURITY_CONTEXT = 0x0099;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_SECURITY_CONTEXT); }))) {
            mixin(enumMixinStr_LDAP_OPT_SECURITY_CONTEXT);
        }
    }




    static if(!is(typeof(LDAP_OPT_SASL_METHOD))) {
        private enum enumMixinStr_LDAP_OPT_SASL_METHOD = `enum LDAP_OPT_SASL_METHOD = 0x0097;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_SASL_METHOD); }))) {
            mixin(enumMixinStr_LDAP_OPT_SASL_METHOD);
        }
    }




    static if(!is(typeof(LDAP_OPT_ENCRYPT))) {
        private enum enumMixinStr_LDAP_OPT_ENCRYPT = `enum LDAP_OPT_ENCRYPT = 0x0096;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_ENCRYPT); }))) {
            mixin(enumMixinStr_LDAP_OPT_ENCRYPT);
        }
    }




    static if(!is(typeof(LDAP_OPT_SIGN))) {
        private enum enumMixinStr_LDAP_OPT_SIGN = `enum LDAP_OPT_SIGN = 0x0095;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_SIGN); }))) {
            mixin(enumMixinStr_LDAP_OPT_SIGN);
        }
    }




    static if(!is(typeof(LDAP_OPT_SSPI_FLAGS))) {
        private enum enumMixinStr_LDAP_OPT_SSPI_FLAGS = `enum LDAP_OPT_SSPI_FLAGS = 0x0092;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_SSPI_FLAGS); }))) {
            mixin(enumMixinStr_LDAP_OPT_SSPI_FLAGS);
        }
    }




    static if(!is(typeof(LDAP_OPT_MATCHED_DN))) {
        private enum enumMixinStr_LDAP_OPT_MATCHED_DN = `enum LDAP_OPT_MATCHED_DN = 0x0033;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_MATCHED_DN); }))) {
            mixin(enumMixinStr_LDAP_OPT_MATCHED_DN);
        }
    }




    static if(!is(typeof(LDAP_OPT_ERROR_STRING))) {
        private enum enumMixinStr_LDAP_OPT_ERROR_STRING = `enum LDAP_OPT_ERROR_STRING = LDAP_OPT_DIAGNOSTIC_MESSAGE;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_ERROR_STRING); }))) {
            mixin(enumMixinStr_LDAP_OPT_ERROR_STRING);
        }
    }




    static if(!is(typeof(LDAP_OPT_DIAGNOSTIC_MESSAGE))) {
        private enum enumMixinStr_LDAP_OPT_DIAGNOSTIC_MESSAGE = `enum LDAP_OPT_DIAGNOSTIC_MESSAGE = 0x0032;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_DIAGNOSTIC_MESSAGE); }))) {
            mixin(enumMixinStr_LDAP_OPT_DIAGNOSTIC_MESSAGE);
        }
    }




    static if(!is(typeof(LDAP_OPT_ERROR_NUMBER))) {
        private enum enumMixinStr_LDAP_OPT_ERROR_NUMBER = `enum LDAP_OPT_ERROR_NUMBER = LDAP_OPT_RESULT_CODE;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_ERROR_NUMBER); }))) {
            mixin(enumMixinStr_LDAP_OPT_ERROR_NUMBER);
        }
    }




    static if(!is(typeof(LDAP_OPT_RESULT_CODE))) {
        private enum enumMixinStr_LDAP_OPT_RESULT_CODE = `enum LDAP_OPT_RESULT_CODE = 0x0031;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_RESULT_CODE); }))) {
            mixin(enumMixinStr_LDAP_OPT_RESULT_CODE);
        }
    }




    static if(!is(typeof(LDAP_OPT_HOST_NAME))) {
        private enum enumMixinStr_LDAP_OPT_HOST_NAME = `enum LDAP_OPT_HOST_NAME = 0x0030;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_HOST_NAME); }))) {
            mixin(enumMixinStr_LDAP_OPT_HOST_NAME);
        }
    }




    static if(!is(typeof(LDAP_OPT_API_FEATURE_INFO))) {
        private enum enumMixinStr_LDAP_OPT_API_FEATURE_INFO = `enum LDAP_OPT_API_FEATURE_INFO = 0x0015;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_API_FEATURE_INFO); }))) {
            mixin(enumMixinStr_LDAP_OPT_API_FEATURE_INFO);
        }
    }




    static if(!is(typeof(LDAP_OPT_CLIENT_CONTROLS))) {
        private enum enumMixinStr_LDAP_OPT_CLIENT_CONTROLS = `enum LDAP_OPT_CLIENT_CONTROLS = 0x0013;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_CLIENT_CONTROLS); }))) {
            mixin(enumMixinStr_LDAP_OPT_CLIENT_CONTROLS);
        }
    }




    static if(!is(typeof(LDAP_OPT_SERVER_CONTROLS))) {
        private enum enumMixinStr_LDAP_OPT_SERVER_CONTROLS = `enum LDAP_OPT_SERVER_CONTROLS = 0x0012;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_SERVER_CONTROLS); }))) {
            mixin(enumMixinStr_LDAP_OPT_SERVER_CONTROLS);
        }
    }




    static if(!is(typeof(LDAP_OPT_PROTOCOL_VERSION))) {
        private enum enumMixinStr_LDAP_OPT_PROTOCOL_VERSION = `enum LDAP_OPT_PROTOCOL_VERSION = 0x0011;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_PROTOCOL_VERSION); }))) {
            mixin(enumMixinStr_LDAP_OPT_PROTOCOL_VERSION);
        }
    }




    static if(!is(typeof(LDAP_OPT_RESTART))) {
        private enum enumMixinStr_LDAP_OPT_RESTART = `enum LDAP_OPT_RESTART = 0x0009;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_RESTART); }))) {
            mixin(enumMixinStr_LDAP_OPT_RESTART);
        }
    }




    static if(!is(typeof(LDAP_OPT_REFERRALS))) {
        private enum enumMixinStr_LDAP_OPT_REFERRALS = `enum LDAP_OPT_REFERRALS = 0x0008;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_REFERRALS); }))) {
            mixin(enumMixinStr_LDAP_OPT_REFERRALS);
        }
    }




    static if(!is(typeof(LDAP_OPT_TIMELIMIT))) {
        private enum enumMixinStr_LDAP_OPT_TIMELIMIT = `enum LDAP_OPT_TIMELIMIT = 0x0004;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_TIMELIMIT); }))) {
            mixin(enumMixinStr_LDAP_OPT_TIMELIMIT);
        }
    }




    static if(!is(typeof(LDAP_OPT_SIZELIMIT))) {
        private enum enumMixinStr_LDAP_OPT_SIZELIMIT = `enum LDAP_OPT_SIZELIMIT = 0x0003;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_SIZELIMIT); }))) {
            mixin(enumMixinStr_LDAP_OPT_SIZELIMIT);
        }
    }




    static if(!is(typeof(LDAP_OPT_DEREF))) {
        private enum enumMixinStr_LDAP_OPT_DEREF = `enum LDAP_OPT_DEREF = 0x0002;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_DEREF); }))) {
            mixin(enumMixinStr_LDAP_OPT_DEREF);
        }
    }




    static if(!is(typeof(LDAP_OPT_DESC))) {
        private enum enumMixinStr_LDAP_OPT_DESC = `enum LDAP_OPT_DESC = 0x0001;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_DESC); }))) {
            mixin(enumMixinStr_LDAP_OPT_DESC);
        }
    }




    static if(!is(typeof(LDAP_OPT_API_INFO))) {
        private enum enumMixinStr_LDAP_OPT_API_INFO = `enum LDAP_OPT_API_INFO = 0x0000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_OPT_API_INFO); }))) {
            mixin(enumMixinStr_LDAP_OPT_API_INFO);
        }
    }




    static if(!is(typeof(LDAP_MAXINT))) {
        private enum enumMixinStr_LDAP_MAXINT = `enum LDAP_MAXINT = ( 2147483647 );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_MAXINT); }))) {
            mixin(enumMixinStr_LDAP_MAXINT);
        }
    }




    static if(!is(typeof(LDAP_ALL_OPERATIONAL_ATTRIBUTES))) {
        private enum enumMixinStr_LDAP_ALL_OPERATIONAL_ATTRIBUTES = `enum LDAP_ALL_OPERATIONAL_ATTRIBUTES = "+";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_ALL_OPERATIONAL_ATTRIBUTES); }))) {
            mixin(enumMixinStr_LDAP_ALL_OPERATIONAL_ATTRIBUTES);
        }
    }




    static if(!is(typeof(LDAP_ALL_USER_ATTRIBUTES))) {
        private enum enumMixinStr_LDAP_ALL_USER_ATTRIBUTES = `enum LDAP_ALL_USER_ATTRIBUTES = "*";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_ALL_USER_ATTRIBUTES); }))) {
            mixin(enumMixinStr_LDAP_ALL_USER_ATTRIBUTES);
        }
    }




    static if(!is(typeof(LDAP_NO_ATTRS))) {
        private enum enumMixinStr_LDAP_NO_ATTRS = `enum LDAP_NO_ATTRS = "1.1";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_NO_ATTRS); }))) {
            mixin(enumMixinStr_LDAP_NO_ATTRS);
        }
    }




    static if(!is(typeof(LDAP_ROOT_DSE))) {
        private enum enumMixinStr_LDAP_ROOT_DSE = `enum LDAP_ROOT_DSE = "";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_ROOT_DSE); }))) {
            mixin(enumMixinStr_LDAP_ROOT_DSE);
        }
    }




    static if(!is(typeof(LDAPS_PORT))) {
        private enum enumMixinStr_LDAPS_PORT = `enum LDAPS_PORT = 636;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAPS_PORT); }))) {
            mixin(enumMixinStr_LDAPS_PORT);
        }
    }




    static if(!is(typeof(LDAP_PORT))) {
        private enum enumMixinStr_LDAP_PORT = `enum LDAP_PORT = 389;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_PORT); }))) {
            mixin(enumMixinStr_LDAP_PORT);
        }
    }




    static if(!is(typeof(LDAP_API_FEATURE_X_OPENLDAP))) {
        private enum enumMixinStr_LDAP_API_FEATURE_X_OPENLDAP = `enum LDAP_API_FEATURE_X_OPENLDAP = LDAP_VENDOR_VERSION;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_X_OPENLDAP); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_X_OPENLDAP);
        }
    }




    static if(!is(typeof(LDAP_VENDOR_NAME))) {
        private enum enumMixinStr_LDAP_VENDOR_NAME = `enum LDAP_VENDOR_NAME = "OpenLDAP";`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VENDOR_NAME); }))) {
            mixin(enumMixinStr_LDAP_VENDOR_NAME);
        }
    }




    static if(!is(typeof(LDAP_API_VERSION))) {
        private enum enumMixinStr_LDAP_API_VERSION = `enum LDAP_API_VERSION = 3001;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_VERSION); }))) {
            mixin(enumMixinStr_LDAP_API_VERSION);
        }
    }




    static if(!is(typeof(LDAP_VERSION_MAX))) {
        private enum enumMixinStr_LDAP_VERSION_MAX = `enum LDAP_VERSION_MAX = LDAP_VERSION3;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VERSION_MAX); }))) {
            mixin(enumMixinStr_LDAP_VERSION_MAX);
        }
    }




    static if(!is(typeof(LDAP_VERSION))) {
        private enum enumMixinStr_LDAP_VERSION = `enum LDAP_VERSION = LDAP_VERSION2;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VERSION); }))) {
            mixin(enumMixinStr_LDAP_VERSION);
        }
    }




    static if(!is(typeof(LDAP_VERSION_MIN))) {
        private enum enumMixinStr_LDAP_VERSION_MIN = `enum LDAP_VERSION_MIN = LDAP_VERSION2;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VERSION_MIN); }))) {
            mixin(enumMixinStr_LDAP_VERSION_MIN);
        }
    }




    static if(!is(typeof(LDAP_VERSION3))) {
        private enum enumMixinStr_LDAP_VERSION3 = `enum LDAP_VERSION3 = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VERSION3); }))) {
            mixin(enumMixinStr_LDAP_VERSION3);
        }
    }




    static if(!is(typeof(LDAP_VERSION2))) {
        private enum enumMixinStr_LDAP_VERSION2 = `enum LDAP_VERSION2 = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VERSION2); }))) {
            mixin(enumMixinStr_LDAP_VERSION2);
        }
    }




    static if(!is(typeof(LDAP_VERSION1))) {
        private enum enumMixinStr_LDAP_VERSION1 = `enum LDAP_VERSION1 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VERSION1); }))) {
            mixin(enumMixinStr_LDAP_VERSION1);
        }
    }






    static if(!is(typeof(LBER_LEN_T))) {
        private enum enumMixinStr_LBER_LEN_T = `enum LBER_LEN_T = long;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_LEN_T); }))) {
            mixin(enumMixinStr_LBER_LEN_T);
        }
    }




    static if(!is(typeof(LBER_SOCKET_T))) {
        private enum enumMixinStr_LBER_SOCKET_T = `enum LBER_SOCKET_T = int;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SOCKET_T); }))) {
            mixin(enumMixinStr_LBER_SOCKET_T);
        }
    }




    static if(!is(typeof(LBER_TAG_T))) {
        private enum enumMixinStr_LBER_TAG_T = `enum LBER_TAG_T = long;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_TAG_T); }))) {
            mixin(enumMixinStr_LBER_TAG_T);
        }
    }




    static if(!is(typeof(LBER_INT_T))) {
        private enum enumMixinStr_LBER_INT_T = `enum LBER_INT_T = int;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_INT_T); }))) {
            mixin(enumMixinStr_LBER_INT_T);
        }
    }






    static if(!is(typeof(LBER_ERROR_MEMORY))) {
        private enum enumMixinStr_LBER_ERROR_MEMORY = `enum LBER_ERROR_MEMORY = 0x2;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_ERROR_MEMORY); }))) {
            mixin(enumMixinStr_LBER_ERROR_MEMORY);
        }
    }




    static if(!is(typeof(LBER_ERROR_PARAM))) {
        private enum enumMixinStr_LBER_ERROR_PARAM = `enum LBER_ERROR_PARAM = 0x1;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_ERROR_PARAM); }))) {
            mixin(enumMixinStr_LBER_ERROR_PARAM);
        }
    }




    static if(!is(typeof(LBER_ERROR_NONE))) {
        private enum enumMixinStr_LBER_ERROR_NONE = `enum LBER_ERROR_NONE = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_ERROR_NONE); }))) {
            mixin(enumMixinStr_LBER_ERROR_NONE);
        }
    }




    static if(!is(typeof(ber_errno))) {
        private enum enumMixinStr_ber_errno = `enum ber_errno = ( * ( ber_errno_addr ) ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_ber_errno); }))) {
            mixin(enumMixinStr_ber_errno);
        }
    }
    static if(!is(typeof(LBER_FLUSH_FREE_ALWAYS))) {
        private enum enumMixinStr_LBER_FLUSH_FREE_ALWAYS = `enum LBER_FLUSH_FREE_ALWAYS = ( LBER_FLUSH_FREE_ON_SUCCESS | LBER_FLUSH_FREE_ON_ERROR );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_FLUSH_FREE_ALWAYS); }))) {
            mixin(enumMixinStr_LBER_FLUSH_FREE_ALWAYS);
        }
    }




    static if(!is(typeof(LBER_FLUSH_FREE_ON_ERROR))) {
        private enum enumMixinStr_LBER_FLUSH_FREE_ON_ERROR = `enum LBER_FLUSH_FREE_ON_ERROR = ( 0x2 );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_FLUSH_FREE_ON_ERROR); }))) {
            mixin(enumMixinStr_LBER_FLUSH_FREE_ON_ERROR);
        }
    }




    static if(!is(typeof(LBER_FLUSH_FREE_ON_SUCCESS))) {
        private enum enumMixinStr_LBER_FLUSH_FREE_ON_SUCCESS = `enum LBER_FLUSH_FREE_ON_SUCCESS = ( 0x1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_FLUSH_FREE_ON_SUCCESS); }))) {
            mixin(enumMixinStr_LBER_FLUSH_FREE_ON_SUCCESS);
        }
    }




    static if(!is(typeof(LBER_FLUSH_FREE_NEVER))) {
        private enum enumMixinStr_LBER_FLUSH_FREE_NEVER = `enum LBER_FLUSH_FREE_NEVER = ( 0x0 );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_FLUSH_FREE_NEVER); }))) {
            mixin(enumMixinStr_LBER_FLUSH_FREE_NEVER);
        }
    }




    static if(!is(typeof(LBER_BV_STRING))) {
        private enum enumMixinStr_LBER_BV_STRING = `enum LBER_BV_STRING = 0x04;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_BV_STRING); }))) {
            mixin(enumMixinStr_LBER_BV_STRING);
        }
    }




    static if(!is(typeof(LBER_BV_NOTERM))) {
        private enum enumMixinStr_LBER_BV_NOTERM = `enum LBER_BV_NOTERM = 0x02;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_BV_NOTERM); }))) {
            mixin(enumMixinStr_LBER_BV_NOTERM);
        }
    }




    static if(!is(typeof(LBER_BV_ALLOC))) {
        private enum enumMixinStr_LBER_BV_ALLOC = `enum LBER_BV_ALLOC = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_BV_ALLOC); }))) {
            mixin(enumMixinStr_LBER_BV_ALLOC);
        }
    }
    static if(!is(typeof(LBER_OPT_ERROR))) {
        private enum enumMixinStr_LBER_OPT_ERROR = `enum LBER_OPT_ERROR = ( - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_ERROR); }))) {
            mixin(enumMixinStr_LBER_OPT_ERROR);
        }
    }




    static if(!is(typeof(LBER_OPT_SUCCESS))) {
        private enum enumMixinStr_LBER_OPT_SUCCESS = `enum LBER_OPT_SUCCESS = ( 0 );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_SUCCESS); }))) {
            mixin(enumMixinStr_LBER_OPT_SUCCESS);
        }
    }




    static if(!is(typeof(LBER_OPT_OFF))) {
        private enum enumMixinStr_LBER_OPT_OFF = `enum LBER_OPT_OFF = ( cast( void * ) 0 );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_OFF); }))) {
            mixin(enumMixinStr_LBER_OPT_OFF);
        }
    }




    static if(!is(typeof(LBER_OPT_ON))) {
        private enum enumMixinStr_LBER_OPT_ON = `enum LBER_OPT_ON = ( cast( void * ) & ber_pvt_opt_on );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_ON); }))) {
            mixin(enumMixinStr_LBER_OPT_ON);
        }
    }




    static if(!is(typeof(LBER_OPT_SOCKBUF_DEBUG))) {
        private enum enumMixinStr_LBER_OPT_SOCKBUF_DEBUG = `enum LBER_OPT_SOCKBUF_DEBUG = 0x1002;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_SOCKBUF_DEBUG); }))) {
            mixin(enumMixinStr_LBER_OPT_SOCKBUF_DEBUG);
        }
    }




    static if(!is(typeof(LBER_OPT_SOCKBUF_OPTIONS))) {
        private enum enumMixinStr_LBER_OPT_SOCKBUF_OPTIONS = `enum LBER_OPT_SOCKBUF_OPTIONS = 0x1001;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_SOCKBUF_OPTIONS); }))) {
            mixin(enumMixinStr_LBER_OPT_SOCKBUF_OPTIONS);
        }
    }




    static if(!is(typeof(LBER_OPT_SOCKBUF_DESC))) {
        private enum enumMixinStr_LBER_OPT_SOCKBUF_DESC = `enum LBER_OPT_SOCKBUF_DESC = 0x1000;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_SOCKBUF_DESC); }))) {
            mixin(enumMixinStr_LBER_OPT_SOCKBUF_DESC);
        }
    }




    static if(!is(typeof(LBER_SBIOD_LEVEL_APPLICATION))) {
        private enum enumMixinStr_LBER_SBIOD_LEVEL_APPLICATION = `enum LBER_SBIOD_LEVEL_APPLICATION = 30;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SBIOD_LEVEL_APPLICATION); }))) {
            mixin(enumMixinStr_LBER_SBIOD_LEVEL_APPLICATION);
        }
    }




    static if(!is(typeof(LBER_SBIOD_LEVEL_TRANSPORT))) {
        private enum enumMixinStr_LBER_SBIOD_LEVEL_TRANSPORT = `enum LBER_SBIOD_LEVEL_TRANSPORT = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SBIOD_LEVEL_TRANSPORT); }))) {
            mixin(enumMixinStr_LBER_SBIOD_LEVEL_TRANSPORT);
        }
    }




    static if(!is(typeof(LBER_SBIOD_LEVEL_PROVIDER))) {
        private enum enumMixinStr_LBER_SBIOD_LEVEL_PROVIDER = `enum LBER_SBIOD_LEVEL_PROVIDER = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SBIOD_LEVEL_PROVIDER); }))) {
            mixin(enumMixinStr_LBER_SBIOD_LEVEL_PROVIDER);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_OPT_MAX))) {
        private enum enumMixinStr_LBER_SB_OPT_OPT_MAX = `enum LBER_SB_OPT_OPT_MAX = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_OPT_MAX); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_OPT_MAX);
        }
    }




    static if(!is(typeof(LDAP_API_FEATURE_CANCEL))) {
        private enum enumMixinStr_LDAP_API_FEATURE_CANCEL = `enum LDAP_API_FEATURE_CANCEL = 1000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_CANCEL); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_CANCEL);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_UNGET_BUF))) {
        private enum enumMixinStr_LBER_SB_OPT_UNGET_BUF = `enum LBER_SB_OPT_UNGET_BUF = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_UNGET_BUF); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_UNGET_BUF);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_SET_MAX_INCOMING))) {
        private enum enumMixinStr_LBER_SB_OPT_SET_MAX_INCOMING = `enum LBER_SB_OPT_SET_MAX_INCOMING = 14;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_SET_MAX_INCOMING); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_SET_MAX_INCOMING);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_GET_MAX_INCOMING))) {
        private enum enumMixinStr_LBER_SB_OPT_GET_MAX_INCOMING = `enum LBER_SB_OPT_GET_MAX_INCOMING = 13;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_GET_MAX_INCOMING); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_GET_MAX_INCOMING);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_NEEDS_WRITE))) {
        private enum enumMixinStr_LBER_SB_OPT_NEEDS_WRITE = `enum LBER_SB_OPT_NEEDS_WRITE = 12;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_NEEDS_WRITE); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_NEEDS_WRITE);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_NEEDS_READ))) {
        private enum enumMixinStr_LBER_SB_OPT_NEEDS_READ = `enum LBER_SB_OPT_NEEDS_READ = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_NEEDS_READ); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_NEEDS_READ);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_DRAIN))) {
        private enum enumMixinStr_LBER_SB_OPT_DRAIN = `enum LBER_SB_OPT_DRAIN = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_DRAIN); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_DRAIN);
        }
    }




    static if(!is(typeof(LDAP_API_FEATURE_TURN))) {
        private enum enumMixinStr_LDAP_API_FEATURE_TURN = `enum LDAP_API_FEATURE_TURN = 1000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_TURN); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_TURN);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_SET_READAHEAD))) {
        private enum enumMixinStr_LBER_SB_OPT_SET_READAHEAD = `enum LBER_SB_OPT_SET_READAHEAD = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_SET_READAHEAD); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_SET_READAHEAD);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_DATA_READY))) {
        private enum enumMixinStr_LBER_SB_OPT_DATA_READY = `enum LBER_SB_OPT_DATA_READY = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_DATA_READY); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_DATA_READY);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_GET_SSL))) {
        private enum enumMixinStr_LBER_SB_OPT_GET_SSL = `enum LBER_SB_OPT_GET_SSL = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_GET_SSL); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_GET_SSL);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_SET_NONBLOCK))) {
        private enum enumMixinStr_LBER_SB_OPT_SET_NONBLOCK = `enum LBER_SB_OPT_SET_NONBLOCK = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_SET_NONBLOCK); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_SET_NONBLOCK);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_HAS_IO))) {
        private enum enumMixinStr_LBER_SB_OPT_HAS_IO = `enum LBER_SB_OPT_HAS_IO = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_HAS_IO); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_HAS_IO);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_SET_FD))) {
        private enum enumMixinStr_LBER_SB_OPT_SET_FD = `enum LBER_SB_OPT_SET_FD = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_SET_FD); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_SET_FD);
        }
    }




    static if(!is(typeof(LBER_SB_OPT_GET_FD))) {
        private enum enumMixinStr_LBER_SB_OPT_GET_FD = `enum LBER_SB_OPT_GET_FD = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SB_OPT_GET_FD); }))) {
            mixin(enumMixinStr_LBER_SB_OPT_GET_FD);
        }
    }




    static if(!is(typeof(LBER_OPT_LOG_PROC))) {
        private enum enumMixinStr_LBER_OPT_LOG_PROC = `enum LBER_OPT_LOG_PROC = 0x8006;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_LOG_PROC); }))) {
            mixin(enumMixinStr_LBER_OPT_LOG_PROC);
        }
    }




    static if(!is(typeof(LDAP_API_FEATURE_PAGED_RESULTS))) {
        private enum enumMixinStr_LDAP_API_FEATURE_PAGED_RESULTS = `enum LDAP_API_FEATURE_PAGED_RESULTS = 2000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_PAGED_RESULTS); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_PAGED_RESULTS);
        }
    }




    static if(!is(typeof(LBER_OPT_MEMORY_INUSE))) {
        private enum enumMixinStr_LBER_OPT_MEMORY_INUSE = `enum LBER_OPT_MEMORY_INUSE = 0x8005;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_MEMORY_INUSE); }))) {
            mixin(enumMixinStr_LBER_OPT_MEMORY_INUSE);
        }
    }




    static if(!is(typeof(LBER_OPT_LOG_PRINT_FILE))) {
        private enum enumMixinStr_LBER_OPT_LOG_PRINT_FILE = `enum LBER_OPT_LOG_PRINT_FILE = 0x8004;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_LOG_PRINT_FILE); }))) {
            mixin(enumMixinStr_LBER_OPT_LOG_PRINT_FILE);
        }
    }




    static if(!is(typeof(LBER_OPT_ERROR_FN))) {
        private enum enumMixinStr_LBER_OPT_ERROR_FN = `enum LBER_OPT_ERROR_FN = 0x8003;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_ERROR_FN); }))) {
            mixin(enumMixinStr_LBER_OPT_ERROR_FN);
        }
    }




    static if(!is(typeof(LBER_OPT_MEMORY_FNS))) {
        private enum enumMixinStr_LBER_OPT_MEMORY_FNS = `enum LBER_OPT_MEMORY_FNS = 0x8002;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_MEMORY_FNS); }))) {
            mixin(enumMixinStr_LBER_OPT_MEMORY_FNS);
        }
    }




    static if(!is(typeof(LBER_OPT_LOG_PRINT_FN))) {
        private enum enumMixinStr_LBER_OPT_LOG_PRINT_FN = `enum LBER_OPT_LOG_PRINT_FN = 0x8001;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_LOG_PRINT_FN); }))) {
            mixin(enumMixinStr_LBER_OPT_LOG_PRINT_FN);
        }
    }




    static if(!is(typeof(LBER_OPT_BYTES_TO_WRITE))) {
        private enum enumMixinStr_LBER_OPT_BYTES_TO_WRITE = `enum LBER_OPT_BYTES_TO_WRITE = LBER_OPT_BER_BYTES_TO_WRITE;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_BYTES_TO_WRITE); }))) {
            mixin(enumMixinStr_LBER_OPT_BYTES_TO_WRITE);
        }
    }




    static if(!is(typeof(LBER_OPT_TOTAL_BYTES))) {
        private enum enumMixinStr_LBER_OPT_TOTAL_BYTES = `enum LBER_OPT_TOTAL_BYTES = LBER_OPT_BER_TOTAL_BYTES;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_TOTAL_BYTES); }))) {
            mixin(enumMixinStr_LBER_OPT_TOTAL_BYTES);
        }
    }




    static if(!is(typeof(LBER_OPT_REMAINING_BYTES))) {
        private enum enumMixinStr_LBER_OPT_REMAINING_BYTES = `enum LBER_OPT_REMAINING_BYTES = LBER_OPT_BER_REMAINING_BYTES;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_REMAINING_BYTES); }))) {
            mixin(enumMixinStr_LBER_OPT_REMAINING_BYTES);
        }
    }




    static if(!is(typeof(LBER_OPT_DEBUG_LEVEL))) {
        private enum enumMixinStr_LBER_OPT_DEBUG_LEVEL = `enum LBER_OPT_DEBUG_LEVEL = LBER_OPT_BER_DEBUG;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_DEBUG_LEVEL); }))) {
            mixin(enumMixinStr_LBER_OPT_DEBUG_LEVEL);
        }
    }




    static if(!is(typeof(LDAP_API_FEATURE_SERVER_SIDE_SORT))) {
        private enum enumMixinStr_LDAP_API_FEATURE_SERVER_SIDE_SORT = `enum LDAP_API_FEATURE_SERVER_SIDE_SORT = 2000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_SERVER_SIDE_SORT); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_SERVER_SIDE_SORT);
        }
    }




    static if(!is(typeof(LBER_OPT_BER_MEMCTX))) {
        private enum enumMixinStr_LBER_OPT_BER_MEMCTX = `enum LBER_OPT_BER_MEMCTX = 0x06;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_BER_MEMCTX); }))) {
            mixin(enumMixinStr_LBER_OPT_BER_MEMCTX);
        }
    }




    static if(!is(typeof(LBER_OPT_BER_BYTES_TO_WRITE))) {
        private enum enumMixinStr_LBER_OPT_BER_BYTES_TO_WRITE = `enum LBER_OPT_BER_BYTES_TO_WRITE = 0x05;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_BER_BYTES_TO_WRITE); }))) {
            mixin(enumMixinStr_LBER_OPT_BER_BYTES_TO_WRITE);
        }
    }




    static if(!is(typeof(LBER_OPT_BER_TOTAL_BYTES))) {
        private enum enumMixinStr_LBER_OPT_BER_TOTAL_BYTES = `enum LBER_OPT_BER_TOTAL_BYTES = 0x04;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_BER_TOTAL_BYTES); }))) {
            mixin(enumMixinStr_LBER_OPT_BER_TOTAL_BYTES);
        }
    }




    static if(!is(typeof(LBER_OPT_BER_REMAINING_BYTES))) {
        private enum enumMixinStr_LBER_OPT_BER_REMAINING_BYTES = `enum LBER_OPT_BER_REMAINING_BYTES = 0x03;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_BER_REMAINING_BYTES); }))) {
            mixin(enumMixinStr_LBER_OPT_BER_REMAINING_BYTES);
        }
    }




    static if(!is(typeof(LBER_OPT_BER_DEBUG))) {
        private enum enumMixinStr_LBER_OPT_BER_DEBUG = `enum LBER_OPT_BER_DEBUG = 0x02;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_BER_DEBUG); }))) {
            mixin(enumMixinStr_LBER_OPT_BER_DEBUG);
        }
    }




    static if(!is(typeof(LBER_OPT_BER_OPTIONS))) {
        private enum enumMixinStr_LBER_OPT_BER_OPTIONS = `enum LBER_OPT_BER_OPTIONS = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OPT_BER_OPTIONS); }))) {
            mixin(enumMixinStr_LBER_OPT_BER_OPTIONS);
        }
    }




    static if(!is(typeof(LBER_USE_DER))) {
        private enum enumMixinStr_LBER_USE_DER = `enum LBER_USE_DER = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_USE_DER); }))) {
            mixin(enumMixinStr_LBER_USE_DER);
        }
    }




    static if(!is(typeof(LBER_SET))) {
        private enum enumMixinStr_LBER_SET = `enum LBER_SET = ( cast( ber_tag_t ) 0x31UL );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SET); }))) {
            mixin(enumMixinStr_LBER_SET);
        }
    }




    static if(!is(typeof(LBER_SEQUENCE))) {
        private enum enumMixinStr_LBER_SEQUENCE = `enum LBER_SEQUENCE = ( cast( ber_tag_t ) 0x30UL );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_SEQUENCE); }))) {
            mixin(enumMixinStr_LBER_SEQUENCE);
        }
    }




    static if(!is(typeof(LBER_ENUMERATED))) {
        private enum enumMixinStr_LBER_ENUMERATED = `enum LBER_ENUMERATED = ( cast( ber_tag_t ) 0x0aUL );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_ENUMERATED); }))) {
            mixin(enumMixinStr_LBER_ENUMERATED);
        }
    }




    static if(!is(typeof(LBER_NULL))) {
        private enum enumMixinStr_LBER_NULL = `enum LBER_NULL = ( cast( ber_tag_t ) 0x05UL );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_NULL); }))) {
            mixin(enumMixinStr_LBER_NULL);
        }
    }




    static if(!is(typeof(LBER_OCTETSTRING))) {
        private enum enumMixinStr_LBER_OCTETSTRING = `enum LBER_OCTETSTRING = ( cast( ber_tag_t ) 0x04UL );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_OCTETSTRING); }))) {
            mixin(enumMixinStr_LBER_OCTETSTRING);
        }
    }




    static if(!is(typeof(LBER_BITSTRING))) {
        private enum enumMixinStr_LBER_BITSTRING = `enum LBER_BITSTRING = ( cast( ber_tag_t ) 0x03UL );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_BITSTRING); }))) {
            mixin(enumMixinStr_LBER_BITSTRING);
        }
    }




    static if(!is(typeof(LBER_INTEGER))) {
        private enum enumMixinStr_LBER_INTEGER = `enum LBER_INTEGER = ( cast( ber_tag_t ) 0x02UL );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_INTEGER); }))) {
            mixin(enumMixinStr_LBER_INTEGER);
        }
    }




    static if(!is(typeof(LBER_BOOLEAN))) {
        private enum enumMixinStr_LBER_BOOLEAN = `enum LBER_BOOLEAN = ( cast( ber_tag_t ) 0x01UL );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_BOOLEAN); }))) {
            mixin(enumMixinStr_LBER_BOOLEAN);
        }
    }




    static if(!is(typeof(LBER_DEFAULT))) {
        private enum enumMixinStr_LBER_DEFAULT = `enum LBER_DEFAULT = ( cast( ber_tag_t ) - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_DEFAULT); }))) {
            mixin(enumMixinStr_LBER_DEFAULT);
        }
    }




    static if(!is(typeof(LBER_ERROR))) {
        private enum enumMixinStr_LBER_ERROR = `enum LBER_ERROR = ( cast( ber_tag_t ) - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_ERROR); }))) {
            mixin(enumMixinStr_LBER_ERROR);
        }
    }




    static if(!is(typeof(LDAP_API_FEATURE_VIRTUAL_LIST_VIEW))) {
        private enum enumMixinStr_LDAP_API_FEATURE_VIRTUAL_LIST_VIEW = `enum LDAP_API_FEATURE_VIRTUAL_LIST_VIEW = 2000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_VIRTUAL_LIST_VIEW); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_VIRTUAL_LIST_VIEW);
        }
    }




    static if(!is(typeof(LBER_MORE_TAG_MASK))) {
        private enum enumMixinStr_LBER_MORE_TAG_MASK = `enum LBER_MORE_TAG_MASK = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_MORE_TAG_MASK); }))) {
            mixin(enumMixinStr_LBER_MORE_TAG_MASK);
        }
    }




    static if(!is(typeof(LBER_BIG_TAG_MASK))) {
        private enum enumMixinStr_LBER_BIG_TAG_MASK = `enum LBER_BIG_TAG_MASK = ( cast( ber_tag_t ) 0x1fU );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_BIG_TAG_MASK); }))) {
            mixin(enumMixinStr_LBER_BIG_TAG_MASK);
        }
    }




    static if(!is(typeof(LBER_ENCODING_MASK))) {
        private enum enumMixinStr_LBER_ENCODING_MASK = `enum LBER_ENCODING_MASK = ( cast( ber_tag_t ) 0x20U );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_ENCODING_MASK); }))) {
            mixin(enumMixinStr_LBER_ENCODING_MASK);
        }
    }




    static if(!is(typeof(LBER_CONSTRUCTED))) {
        private enum enumMixinStr_LBER_CONSTRUCTED = `enum LBER_CONSTRUCTED = ( cast( ber_tag_t ) 0x20U );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_CONSTRUCTED); }))) {
            mixin(enumMixinStr_LBER_CONSTRUCTED);
        }
    }




    static if(!is(typeof(LBER_PRIMITIVE))) {
        private enum enumMixinStr_LBER_PRIMITIVE = `enum LBER_PRIMITIVE = ( cast( ber_tag_t ) 0x00U );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_PRIMITIVE); }))) {
            mixin(enumMixinStr_LBER_PRIMITIVE);
        }
    }




    static if(!is(typeof(LBER_CLASS_MASK))) {
        private enum enumMixinStr_LBER_CLASS_MASK = `enum LBER_CLASS_MASK = ( cast( ber_tag_t ) 0xc0U );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_CLASS_MASK); }))) {
            mixin(enumMixinStr_LBER_CLASS_MASK);
        }
    }




    static if(!is(typeof(LBER_CLASS_PRIVATE))) {
        private enum enumMixinStr_LBER_CLASS_PRIVATE = `enum LBER_CLASS_PRIVATE = ( cast( ber_tag_t ) 0xc0U );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_CLASS_PRIVATE); }))) {
            mixin(enumMixinStr_LBER_CLASS_PRIVATE);
        }
    }




    static if(!is(typeof(LBER_CLASS_CONTEXT))) {
        private enum enumMixinStr_LBER_CLASS_CONTEXT = `enum LBER_CLASS_CONTEXT = ( cast( ber_tag_t ) 0x80U );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_CLASS_CONTEXT); }))) {
            mixin(enumMixinStr_LBER_CLASS_CONTEXT);
        }
    }




    static if(!is(typeof(LBER_CLASS_APPLICATION))) {
        private enum enumMixinStr_LBER_CLASS_APPLICATION = `enum LBER_CLASS_APPLICATION = ( cast( ber_tag_t ) 0x40U );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_CLASS_APPLICATION); }))) {
            mixin(enumMixinStr_LBER_CLASS_APPLICATION);
        }
    }




    static if(!is(typeof(LBER_CLASS_UNIVERSAL))) {
        private enum enumMixinStr_LBER_CLASS_UNIVERSAL = `enum LBER_CLASS_UNIVERSAL = ( cast( ber_tag_t ) 0x00U );`;
        static if(is(typeof({ mixin(enumMixinStr_LBER_CLASS_UNIVERSAL); }))) {
            mixin(enumMixinStr_LBER_CLASS_UNIVERSAL);
        }
    }






    static if(!is(typeof(LDAP_API_FEATURE_WHOAMI))) {
        private enum enumMixinStr_LDAP_API_FEATURE_WHOAMI = `enum LDAP_API_FEATURE_WHOAMI = 1000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_WHOAMI); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_WHOAMI);
        }
    }
    static if(!is(typeof(LDAP_API_FEATURE_PASSWD_MODIFY))) {
        private enum enumMixinStr_LDAP_API_FEATURE_PASSWD_MODIFY = `enum LDAP_API_FEATURE_PASSWD_MODIFY = 1000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_PASSWD_MODIFY); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_PASSWD_MODIFY);
        }
    }
    static if(!is(typeof(__GLIBC_MINOR__))) {
        private enum enumMixinStr___GLIBC_MINOR__ = `enum __GLIBC_MINOR__ = 30;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_MINOR__); }))) {
            mixin(enumMixinStr___GLIBC_MINOR__);
        }
    }




    static if(!is(typeof(__GLIBC__))) {
        private enum enumMixinStr___GLIBC__ = `enum __GLIBC__ = 2;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC__); }))) {
            mixin(enumMixinStr___GLIBC__);
        }
    }




    static if(!is(typeof(__GNU_LIBRARY__))) {
        private enum enumMixinStr___GNU_LIBRARY__ = `enum __GNU_LIBRARY__ = 6;`;
        static if(is(typeof({ mixin(enumMixinStr___GNU_LIBRARY__); }))) {
            mixin(enumMixinStr___GNU_LIBRARY__);
        }
    }




    static if(!is(typeof(__GLIBC_USE_DEPRECATED_SCANF))) {
        private enum enumMixinStr___GLIBC_USE_DEPRECATED_SCANF = `enum __GLIBC_USE_DEPRECATED_SCANF = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_DEPRECATED_SCANF); }))) {
            mixin(enumMixinStr___GLIBC_USE_DEPRECATED_SCANF);
        }
    }




    static if(!is(typeof(__GLIBC_USE_DEPRECATED_GETS))) {
        private enum enumMixinStr___GLIBC_USE_DEPRECATED_GETS = `enum __GLIBC_USE_DEPRECATED_GETS = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_DEPRECATED_GETS); }))) {
            mixin(enumMixinStr___GLIBC_USE_DEPRECATED_GETS);
        }
    }




    static if(!is(typeof(__USE_FORTIFY_LEVEL))) {
        private enum enumMixinStr___USE_FORTIFY_LEVEL = `enum __USE_FORTIFY_LEVEL = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_FORTIFY_LEVEL); }))) {
            mixin(enumMixinStr___USE_FORTIFY_LEVEL);
        }
    }




    static if(!is(typeof(__USE_ATFILE))) {
        private enum enumMixinStr___USE_ATFILE = `enum __USE_ATFILE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_ATFILE); }))) {
            mixin(enumMixinStr___USE_ATFILE);
        }
    }




    static if(!is(typeof(__USE_MISC))) {
        private enum enumMixinStr___USE_MISC = `enum __USE_MISC = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_MISC); }))) {
            mixin(enumMixinStr___USE_MISC);
        }
    }




    static if(!is(typeof(LDAP_API_FEATURE_PASSWORD_POLICY))) {
        private enum enumMixinStr_LDAP_API_FEATURE_PASSWORD_POLICY = `enum LDAP_API_FEATURE_PASSWORD_POLICY = 1000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_PASSWORD_POLICY); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_PASSWORD_POLICY);
        }
    }




    static if(!is(typeof(_ATFILE_SOURCE))) {
        private enum enumMixinStr__ATFILE_SOURCE = `enum _ATFILE_SOURCE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__ATFILE_SOURCE); }))) {
            mixin(enumMixinStr__ATFILE_SOURCE);
        }
    }




    static if(!is(typeof(__USE_XOPEN2K8))) {
        private enum enumMixinStr___USE_XOPEN2K8 = `enum __USE_XOPEN2K8 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_XOPEN2K8); }))) {
            mixin(enumMixinStr___USE_XOPEN2K8);
        }
    }




    static if(!is(typeof(__USE_ISOC99))) {
        private enum enumMixinStr___USE_ISOC99 = `enum __USE_ISOC99 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_ISOC99); }))) {
            mixin(enumMixinStr___USE_ISOC99);
        }
    }




    static if(!is(typeof(__USE_ISOC95))) {
        private enum enumMixinStr___USE_ISOC95 = `enum __USE_ISOC95 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_ISOC95); }))) {
            mixin(enumMixinStr___USE_ISOC95);
        }
    }




    static if(!is(typeof(__USE_XOPEN2K))) {
        private enum enumMixinStr___USE_XOPEN2K = `enum __USE_XOPEN2K = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_XOPEN2K); }))) {
            mixin(enumMixinStr___USE_XOPEN2K);
        }
    }




    static if(!is(typeof(__USE_POSIX199506))) {
        private enum enumMixinStr___USE_POSIX199506 = `enum __USE_POSIX199506 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_POSIX199506); }))) {
            mixin(enumMixinStr___USE_POSIX199506);
        }
    }




    static if(!is(typeof(__USE_POSIX199309))) {
        private enum enumMixinStr___USE_POSIX199309 = `enum __USE_POSIX199309 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_POSIX199309); }))) {
            mixin(enumMixinStr___USE_POSIX199309);
        }
    }




    static if(!is(typeof(__USE_POSIX2))) {
        private enum enumMixinStr___USE_POSIX2 = `enum __USE_POSIX2 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_POSIX2); }))) {
            mixin(enumMixinStr___USE_POSIX2);
        }
    }




    static if(!is(typeof(__USE_POSIX))) {
        private enum enumMixinStr___USE_POSIX = `enum __USE_POSIX = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_POSIX); }))) {
            mixin(enumMixinStr___USE_POSIX);
        }
    }




    static if(!is(typeof(_POSIX_C_SOURCE))) {
        private enum enumMixinStr__POSIX_C_SOURCE = `enum _POSIX_C_SOURCE = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_C_SOURCE); }))) {
            mixin(enumMixinStr__POSIX_C_SOURCE);
        }
    }




    static if(!is(typeof(_POSIX_SOURCE))) {
        private enum enumMixinStr__POSIX_SOURCE = `enum _POSIX_SOURCE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SOURCE); }))) {
            mixin(enumMixinStr__POSIX_SOURCE);
        }
    }




    static if(!is(typeof(LDAP_API_FEATURE_REFRESH))) {
        private enum enumMixinStr_LDAP_API_FEATURE_REFRESH = `enum LDAP_API_FEATURE_REFRESH = 1000;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_REFRESH); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_REFRESH);
        }
    }




    static if(!is(typeof(__USE_POSIX_IMPLICITLY))) {
        private enum enumMixinStr___USE_POSIX_IMPLICITLY = `enum __USE_POSIX_IMPLICITLY = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_POSIX_IMPLICITLY); }))) {
            mixin(enumMixinStr___USE_POSIX_IMPLICITLY);
        }
    }




    static if(!is(typeof(__USE_ISOC11))) {
        private enum enumMixinStr___USE_ISOC11 = `enum __USE_ISOC11 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_ISOC11); }))) {
            mixin(enumMixinStr___USE_ISOC11);
        }
    }




    static if(!is(typeof(_DEFAULT_SOURCE))) {
        private enum enumMixinStr__DEFAULT_SOURCE = `enum _DEFAULT_SOURCE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__DEFAULT_SOURCE); }))) {
            mixin(enumMixinStr__DEFAULT_SOURCE);
        }
    }
    static if(!is(typeof(_FEATURES_H))) {
        private enum enumMixinStr__FEATURES_H = `enum _FEATURES_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__FEATURES_H); }))) {
            mixin(enumMixinStr__FEATURES_H);
        }
    }




    static if(!is(typeof(__SYSCALL_WORDSIZE))) {
        private enum enumMixinStr___SYSCALL_WORDSIZE = `enum __SYSCALL_WORDSIZE = 64;`;
        static if(is(typeof({ mixin(enumMixinStr___SYSCALL_WORDSIZE); }))) {
            mixin(enumMixinStr___SYSCALL_WORDSIZE);
        }
    }




    static if(!is(typeof(__WORDSIZE_TIME64_COMPAT32))) {
        private enum enumMixinStr___WORDSIZE_TIME64_COMPAT32 = `enum __WORDSIZE_TIME64_COMPAT32 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___WORDSIZE_TIME64_COMPAT32); }))) {
            mixin(enumMixinStr___WORDSIZE_TIME64_COMPAT32);
        }
    }




    static if(!is(typeof(__WORDSIZE))) {
        private enum enumMixinStr___WORDSIZE = `enum __WORDSIZE = 64;`;
        static if(is(typeof({ mixin(enumMixinStr___WORDSIZE); }))) {
            mixin(enumMixinStr___WORDSIZE);
        }
    }




    static if(!is(typeof(_BITS_TYPES_LOCALE_T_H))) {
        private enum enumMixinStr__BITS_TYPES_LOCALE_T_H = `enum _BITS_TYPES_LOCALE_T_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_TYPES_LOCALE_T_H); }))) {
            mixin(enumMixinStr__BITS_TYPES_LOCALE_T_H);
        }
    }




    static if(!is(typeof(_BITS_TYPES___LOCALE_T_H))) {
        private enum enumMixinStr__BITS_TYPES___LOCALE_T_H = `enum _BITS_TYPES___LOCALE_T_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_TYPES___LOCALE_T_H); }))) {
            mixin(enumMixinStr__BITS_TYPES___LOCALE_T_H);
        }
    }




    static if(!is(typeof(__GLIBC_USE_IEC_60559_TYPES_EXT))) {
        private enum enumMixinStr___GLIBC_USE_IEC_60559_TYPES_EXT = `enum __GLIBC_USE_IEC_60559_TYPES_EXT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_IEC_60559_TYPES_EXT); }))) {
            mixin(enumMixinStr___GLIBC_USE_IEC_60559_TYPES_EXT);
        }
    }




    static if(!is(typeof(__GLIBC_USE_IEC_60559_FUNCS_EXT))) {
        private enum enumMixinStr___GLIBC_USE_IEC_60559_FUNCS_EXT = `enum __GLIBC_USE_IEC_60559_FUNCS_EXT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_IEC_60559_FUNCS_EXT); }))) {
            mixin(enumMixinStr___GLIBC_USE_IEC_60559_FUNCS_EXT);
        }
    }




    static if(!is(typeof(__GLIBC_USE_IEC_60559_BFP_EXT))) {
        private enum enumMixinStr___GLIBC_USE_IEC_60559_BFP_EXT = `enum __GLIBC_USE_IEC_60559_BFP_EXT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_IEC_60559_BFP_EXT); }))) {
            mixin(enumMixinStr___GLIBC_USE_IEC_60559_BFP_EXT);
        }
    }




    static if(!is(typeof(__GLIBC_USE_LIB_EXT2))) {
        private enum enumMixinStr___GLIBC_USE_LIB_EXT2 = `enum __GLIBC_USE_LIB_EXT2 = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_LIB_EXT2); }))) {
            mixin(enumMixinStr___GLIBC_USE_LIB_EXT2);
        }
    }




    static if(!is(typeof(LDAP_AUTH_NTLM_REQUEST))) {
        private enum enumMixinStr_LDAP_AUTH_NTLM_REQUEST = `enum LDAP_AUTH_NTLM_REQUEST = ( cast( ber_tag_t ) 0x8aU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_NTLM_REQUEST); }))) {
            mixin(enumMixinStr_LDAP_AUTH_NTLM_REQUEST);
        }
    }




    static if(!is(typeof(LDAP_AUTH_NTLM_RESPONSE))) {
        private enum enumMixinStr_LDAP_AUTH_NTLM_RESPONSE = `enum LDAP_AUTH_NTLM_RESPONSE = ( cast( ber_tag_t ) 0x8bU );`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_AUTH_NTLM_RESPONSE); }))) {
            mixin(enumMixinStr_LDAP_AUTH_NTLM_RESPONSE);
        }
    }
    static if(!is(typeof(LDAP_CONST))) {
        private enum enumMixinStr_LDAP_CONST = `enum LDAP_CONST = const;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_CONST); }))) {
            mixin(enumMixinStr_LDAP_CONST);
        }
    }
    static if(!is(typeof(_LDAP_FEATURES_H))) {
        private enum enumMixinStr__LDAP_FEATURES_H = `enum _LDAP_FEATURES_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__LDAP_FEATURES_H); }))) {
            mixin(enumMixinStr__LDAP_FEATURES_H);
        }
    }




    static if(!is(typeof(LDAP_VENDOR_VERSION))) {
        private enum enumMixinStr_LDAP_VENDOR_VERSION = `enum LDAP_VENDOR_VERSION = 20448;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VENDOR_VERSION); }))) {
            mixin(enumMixinStr_LDAP_VENDOR_VERSION);
        }
    }




    static if(!is(typeof(LDAP_VENDOR_VERSION_MAJOR))) {
        private enum enumMixinStr_LDAP_VENDOR_VERSION_MAJOR = `enum LDAP_VENDOR_VERSION_MAJOR = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VENDOR_VERSION_MAJOR); }))) {
            mixin(enumMixinStr_LDAP_VENDOR_VERSION_MAJOR);
        }
    }




    static if(!is(typeof(LDAP_VENDOR_VERSION_MINOR))) {
        private enum enumMixinStr_LDAP_VENDOR_VERSION_MINOR = `enum LDAP_VENDOR_VERSION_MINOR = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VENDOR_VERSION_MINOR); }))) {
            mixin(enumMixinStr_LDAP_VENDOR_VERSION_MINOR);
        }
    }




    static if(!is(typeof(LDAP_VENDOR_VERSION_PATCH))) {
        private enum enumMixinStr_LDAP_VENDOR_VERSION_PATCH = `enum LDAP_VENDOR_VERSION_PATCH = 48;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_VENDOR_VERSION_PATCH); }))) {
            mixin(enumMixinStr_LDAP_VENDOR_VERSION_PATCH);
        }
    }




    static if(!is(typeof(LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE))) {
        private enum enumMixinStr_LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE = `enum LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE); }))) {
            mixin(enumMixinStr_LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE);
        }
    }




    static if(!is(typeof(_STDC_PREDEF_H))) {
        private enum enumMixinStr__STDC_PREDEF_H = `enum _STDC_PREDEF_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STDC_PREDEF_H); }))) {
            mixin(enumMixinStr__STDC_PREDEF_H);
        }
    }




    static if(!is(typeof(_STRING_H))) {
        private enum enumMixinStr__STRING_H = `enum _STRING_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STRING_H); }))) {
            mixin(enumMixinStr__STRING_H);
        }
    }
    static if(!is(typeof(_STRINGS_H))) {
        private enum enumMixinStr__STRINGS_H = `enum _STRINGS_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STRINGS_H); }))) {
            mixin(enumMixinStr__STRINGS_H);
        }
    }




    static if(!is(typeof(_SYS_CDEFS_H))) {
        private enum enumMixinStr__SYS_CDEFS_H = `enum _SYS_CDEFS_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_CDEFS_H); }))) {
            mixin(enumMixinStr__SYS_CDEFS_H);
        }
    }
    static if(!is(typeof(__THROW))) {
        private enum enumMixinStr___THROW = `enum __THROW = __attribute__ ( ( __nothrow__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___THROW); }))) {
            mixin(enumMixinStr___THROW);
        }
    }




    static if(!is(typeof(__THROWNL))) {
        private enum enumMixinStr___THROWNL = `enum __THROWNL = __attribute__ ( ( __nothrow__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___THROWNL); }))) {
            mixin(enumMixinStr___THROWNL);
        }
    }
    static if(!is(typeof(__ptr_t))) {
        private enum enumMixinStr___ptr_t = `enum __ptr_t = void *;`;
        static if(is(typeof({ mixin(enumMixinStr___ptr_t); }))) {
            mixin(enumMixinStr___ptr_t);
        }
    }
    static if(!is(typeof(__flexarr))) {
        private enum enumMixinStr___flexarr = `enum __flexarr = [ ];`;
        static if(is(typeof({ mixin(enumMixinStr___flexarr); }))) {
            mixin(enumMixinStr___flexarr);
        }
    }




    static if(!is(typeof(__glibc_c99_flexarr_available))) {
        private enum enumMixinStr___glibc_c99_flexarr_available = `enum __glibc_c99_flexarr_available = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___glibc_c99_flexarr_available); }))) {
            mixin(enumMixinStr___glibc_c99_flexarr_available);
        }
    }
    static if(!is(typeof(__attribute_malloc__))) {
        private enum enumMixinStr___attribute_malloc__ = `enum __attribute_malloc__ = __attribute__ ( ( __malloc__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_malloc__); }))) {
            mixin(enumMixinStr___attribute_malloc__);
        }
    }






    static if(!is(typeof(__attribute_pure__))) {
        private enum enumMixinStr___attribute_pure__ = `enum __attribute_pure__ = __attribute__ ( ( __pure__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_pure__); }))) {
            mixin(enumMixinStr___attribute_pure__);
        }
    }




    static if(!is(typeof(__attribute_const__))) {
        private enum enumMixinStr___attribute_const__ = `enum __attribute_const__ = __attribute__ ( cast( __const__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_const__); }))) {
            mixin(enumMixinStr___attribute_const__);
        }
    }




    static if(!is(typeof(__attribute_used__))) {
        private enum enumMixinStr___attribute_used__ = `enum __attribute_used__ = __attribute__ ( ( __used__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_used__); }))) {
            mixin(enumMixinStr___attribute_used__);
        }
    }




    static if(!is(typeof(__attribute_noinline__))) {
        private enum enumMixinStr___attribute_noinline__ = `enum __attribute_noinline__ = __attribute__ ( ( __noinline__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_noinline__); }))) {
            mixin(enumMixinStr___attribute_noinline__);
        }
    }




    static if(!is(typeof(__attribute_deprecated__))) {
        private enum enumMixinStr___attribute_deprecated__ = `enum __attribute_deprecated__ = __attribute__ ( ( __deprecated__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_deprecated__); }))) {
            mixin(enumMixinStr___attribute_deprecated__);
        }
    }
    static if(!is(typeof(__attribute_warn_unused_result__))) {
        private enum enumMixinStr___attribute_warn_unused_result__ = `enum __attribute_warn_unused_result__ = __attribute__ ( ( __warn_unused_result__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_warn_unused_result__); }))) {
            mixin(enumMixinStr___attribute_warn_unused_result__);
        }
    }






    static if(!is(typeof(__always_inline))) {
        private enum enumMixinStr___always_inline = `enum __always_inline = __inline __attribute__ ( ( __always_inline__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___always_inline); }))) {
            mixin(enumMixinStr___always_inline);
        }
    }






    static if(!is(typeof(__extern_inline))) {
        private enum enumMixinStr___extern_inline = `enum __extern_inline = extern __inline __attribute__ ( ( __gnu_inline__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___extern_inline); }))) {
            mixin(enumMixinStr___extern_inline);
        }
    }




    static if(!is(typeof(__extern_always_inline))) {
        private enum enumMixinStr___extern_always_inline = `enum __extern_always_inline = extern __inline __attribute__ ( ( __always_inline__ ) ) __attribute__ ( ( __gnu_inline__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___extern_always_inline); }))) {
            mixin(enumMixinStr___extern_always_inline);
        }
    }




    static if(!is(typeof(__fortify_function))) {
        private enum enumMixinStr___fortify_function = `enum __fortify_function = extern __inline __attribute__ ( ( __always_inline__ ) ) __attribute__ ( ( __gnu_inline__ ) ) ;`;
        static if(is(typeof({ mixin(enumMixinStr___fortify_function); }))) {
            mixin(enumMixinStr___fortify_function);
        }
    }




    static if(!is(typeof(__restrict_arr))) {
        private enum enumMixinStr___restrict_arr = `enum __restrict_arr = __restrict;`;
        static if(is(typeof({ mixin(enumMixinStr___restrict_arr); }))) {
            mixin(enumMixinStr___restrict_arr);
        }
    }
    static if(!is(typeof(__glibc_has_include))) {
        private enum enumMixinStr___glibc_has_include = `enum __glibc_has_include = __has_include;`;
        static if(is(typeof({ mixin(enumMixinStr___glibc_has_include); }))) {
            mixin(enumMixinStr___glibc_has_include);
        }
    }
    static if(!is(typeof(__HAVE_GENERIC_SELECTION))) {
        private enum enumMixinStr___HAVE_GENERIC_SELECTION = `enum __HAVE_GENERIC_SELECTION = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_GENERIC_SELECTION); }))) {
            mixin(enumMixinStr___HAVE_GENERIC_SELECTION);
        }
    }






    static if(!is(typeof(NULL))) {
        private enum enumMixinStr_NULL = `enum NULL = ( cast( void * ) 0 );`;
        static if(is(typeof({ mixin(enumMixinStr_NULL); }))) {
            mixin(enumMixinStr_NULL);
        }
    }

}
