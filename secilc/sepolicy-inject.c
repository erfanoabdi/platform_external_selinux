/* 
 * This was derived from public domain works with updates to 
 * work with more modern SELinux libraries. 
 * 
 * It is released into the public domain.
 * 
 */

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#include <sepol/policydb.h>
#include "sepolicy-inject.h"

int set_attr(char *type, int value, policydb_t *policy) {
	type_datum_t *attr = hashtab_search(policy->p_types.table, type);
	if (!attr)
		exit(1);

	if (attr->flavor != TYPE_ATTRIB)
		exit(1);

	if(ebitmap_set_bit(&policy->type_attr_map[value-1], attr->s.value-1, 1))
		exit(1);
	if(ebitmap_set_bit(&policy->attr_type_map[attr->s.value-1], value-1, 1))
		exit(1);

	return 0;
}

void create_domain(char *d, policydb_t *policy) {
	symtab_datum_t *src = hashtab_search(policy->p_types.table, d);
	if(src)
		return;

	type_datum_t *typdatum = (type_datum_t *) malloc(sizeof(type_datum_t));
	type_datum_init(typdatum);
	typdatum->primary = 1;
	typdatum->flavor = TYPE_TYPE;

	uint32_t value = 0;
	int r = symtab_insert(policy, SYM_TYPES, strdup(d), typdatum, SCOPE_DECL, 1, &value);
	typdatum->s.value = value;

	fprintf(stderr, "source type %s does not exist: %d,%d\n", d, r, value);
	if (ebitmap_set_bit(&policy->global->branch_list->declared.scope[SYM_TYPES], value - 1, 1)) {
		exit(1);
	}

	policy->type_attr_map = realloc(policy->type_attr_map, sizeof(ebitmap_t)*policy->p_types.nprim);
	policy->attr_type_map = realloc(policy->attr_type_map, sizeof(ebitmap_t)*policy->p_types.nprim);
	ebitmap_init(&policy->type_attr_map[value-1]);
	ebitmap_init(&policy->attr_type_map[value-1]);
	ebitmap_set_bit(&policy->type_attr_map[value-1], value-1, 1);

	//Add the domain to all roles
	for(unsigned i=0; i<policy->p_roles.nprim; ++i) {
		//Not sure all those three calls are needed
		ebitmap_set_bit(&policy->role_val_to_struct[i]->types.negset, value-1, 0);
		ebitmap_set_bit(&policy->role_val_to_struct[i]->types.types, value-1, 1);
		type_set_expand(&policy->role_val_to_struct[i]->types, &policy->role_val_to_struct[i]->cache, policy, 0);
	}


	src = hashtab_search(policy->p_types.table, d);
	if(!src)
		exit(1);

	extern int policydb_index_decls(policydb_t * p);
	if(policydb_index_decls(policy))
		exit(1);

	if(policydb_index_classes(policy))
		exit(1);

	if(policydb_index_others(NULL, policy, 1))
		exit(1);

	set_attr("domain", value, policy);
}


extern void set_permissive_type(policydb_t *policydb, char *permissive)
{
    type_datum_t *type;
    create_domain(permissive, policydb);
    type = hashtab_search(policydb->p_types.table, permissive);
    if (type == NULL) {
        fprintf(stderr, "type %s does not exist\n", permissive);
    }
    if (ebitmap_set_bit(&policydb->permissive_map, type->s.value, 1)) {
        fprintf(stderr, "Could not set bit in permissive map\n");
    }
}
