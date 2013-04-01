/* * Copyright (c) 2013 Qualcomm Atheros, Inc. */
/*
 * @file
 *  This file contains necessary defines for profiling NSS GMAC driver.
 * -------------------------------------REVISION HISTORY---------------------------
 * Qualcomm Atheros               01/Mar/2010                     Created
 */

#ifndef __NSS_GMAC_PROFILE__
#define __NSS_GMAC_PROFILE__

#undef GMAC_PROFILER
#ifdef GMAC_PROFILER

#define GMAC_PROFILER_VCOUNT_INC(x)	((x)++)
#else
#define GMAC_PROFILER_VCOUNT_INC(x)	do { } while(0)
#endif /* GMAC_PROFILER */

#endif /* End of File */
