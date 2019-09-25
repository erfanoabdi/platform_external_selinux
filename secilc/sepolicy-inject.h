/* 
 * This was derived from public domain works with updates to 
 * work with more modern SELinux libraries. 
 * 
 * It is released into the public domain.
 * 
 */

#ifndef SEPOLICY_INJECT_H_
#define SEPOLICY_INJECT_H_

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void set_permissive_type(policydb_t *policydb, char *permissive);

#ifdef __cplusplus
}
#endif
#endif
