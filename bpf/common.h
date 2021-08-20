#include <linux/swab.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define PIN_GLOBAL_NS		2

#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-id-macro"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohs(x)			__builtin_bswap16(x)
# define __bpf_htons(x)			__builtin_bswap16(x)
# define __bpf_constant_ntohs(x)	___constant_swab16(x)
# define __bpf_constant_htons(x)	___constant_swab16(x)
# define __bpf_ntohl(x)			__builtin_bswap32(x)
# define __bpf_htonl(x)			__builtin_bswap32(x)
# define __bpf_constant_ntohl(x)	___constant_swab32(x)
# define __bpf_constant_htonl(x)	___constant_swab32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohs(x)			(x)
# define __bpf_htons(x)			(x)
# define __bpf_constant_ntohs(x)	(x)
# define __bpf_constant_htons(x)	(x)
# define __bpf_ntohl(x)			(x)
# define __bpf_htonl(x)			(x)
# define __bpf_constant_ntohl(x)	(x)
# define __bpf_constant_htonl(x)	(x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
#pragma clang diagnostic pop

#define bpf_htons(x)				\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_htons(x) : __bpf_htons(x))
#define bpf_ntohs(x)				\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_ntohs(x) : __bpf_ntohs(x))
#define bpf_htonl(x)				\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_htonl(x) : __bpf_htonl(x))
#define bpf_ntohl(x)				\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_ntohl(x) : __bpf_ntohl(x))

struct bpf_elf_map {
    /*
     * The various BPF MAP types supported (see enum bpf_map_type)
     * https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h
     */
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    /*
     * Various flags you can place such as `BPF_F_NO_COMMON_LRU`
     */
    __u32 flags;
    __u32 id;
    /*
     * Pinning is how the map are shared across process boundary.
     * Cillium has a good explanation of them: http://docs.cilium.io/en/v1.3/bpf/#llvm
     * PIN_GLOBAL_NS - will get pinned to `/sys/fs/bpf/tc/globals/${variable-name}`
     * PIN_OBJECT_NS - will get pinned to a directory that is unique to this object
     * PIN_NONE - the map is not placed into the BPF file system as a node,
                   and as a result will not be accessible from user space
     */
    __u32 pinning;
};