#include "uthash.h"
#include <stdio.h>
#include <stdlib.h>  /* malloc */

typedef struct person_t {
    char first_name[10];
    int id;
    UT_hash_handle hh;
} person_t;

int main()
{
    person_t *people=NULL, *person;
    const char **name;
    const char * names[] = { "bob", "jack", "gary", "ty", "bo", "phil", "art",
                             "gil", "buck", "ted", NULL
                           };
    int id=0;

    for(name=names; *name!=NULL; name++) {
        person = (person_t*)malloc(sizeof(person_t));
        if (person == NULL) {
            exit(-1);
        }
        strcpy(person->first_name, *name);
        person->id = id++;
        HASH_ADD_STR(people,first_name,person);
        printf("added %s (id %d)\n", person->first_name, person->id);
    }

    person=NULL;
    person_t **p=&person;

    for(name=names; *name!=NULL; name++) {
        HASH_FIND_STR(people,*name,*p);
        if (person != NULL) {
            printf("found %s (id %d)\n", person->first_name, person->id);
        } else {
            printf("failed to find %s\n", *name);
        }
    }
    return 0;
}
