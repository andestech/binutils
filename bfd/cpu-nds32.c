#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#define N(number,print,default,next) \
    {32, 32, 8, bfd_arch_nds32, number, "nds32", print, 4, default, \
     bfd_default_compatible, bfd_default_scan, bfd_arch_default_fill, next }
#define NEXT &arch_info_struct[0]
#define NDS32V2_NEXT &arch_info_struct[1]
#define NDS32V3_NEXT &arch_info_struct[2]
#define NDS32V3M_NEXT &arch_info_struct[3]
static const bfd_arch_info_type arch_info_struct[] = {
  N (bfd_mach_n1h, "n1h", FALSE, NDS32V2_NEXT),
  N (bfd_mach_n1h_v2, "n1h_v2", FALSE, NDS32V3_NEXT),
  N (bfd_mach_n1h_v3, "n1h_v3", FALSE, NDS32V3M_NEXT),
  N (bfd_mach_n1h_v3m, "n1h_v3m", FALSE, NULL),
};
const bfd_arch_info_type bfd_nds32_arch =
  N (bfd_mach_n1, "n1h", TRUE, NEXT);
