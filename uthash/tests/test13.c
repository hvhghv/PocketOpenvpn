#include "uthash.h"
#include <stdlib.h>   /* malloc */
#include <stdio.h>    /* printf */

typedef struct example_user_t {
    int id;
    int cookie;
    UT_hash_handle hh;
} example_user_t;

int main()
{
    int i;
    example_user_t *user, *tmp, *users=NULL;

    /* create elements */
    for(i=0; i<10; i++) {
        user = (example_user_t*)malloc(sizeof(example_user_t));
        if (user == NULL) {
            exit(-1);
        }
        user->id = i;
        user->cookie = i*i;
        HASH_ADD_INT(users,id,user);
    }

    /* delete each even ID */
    for(i=0; i<10; i+=2) {
        HASH_FIND_INT(users,&i,tmp);
        if (tmp != NULL) {
            HASH_DEL(users,tmp);
            free(tmp);
        } else {
            printf("user id %d not found\n", i);
        }
    }

    i=9;
    HASH_FIND_INT(users,&i,tmp);
    if (tmp != NULL) {
        while (tmp != NULL) {
            printf("id %d, following prev...\n", tmp->id);
            tmp = (example_user_t*)tmp->hh.prev;
        }
    } else {
        printf("user id %d not found\n", i);
    }

    return 0;
}
