
#include <stdlib.h>

#include "dbg.h"
#include "list.h"

List *list_push(List *list, void *value)
{
    List *node = calloc(1, sizeof(List));
    check_mem(node);

    node->value = value;

    if(list)
        node->next = list;

    return node;
error:
    return list;
}

List *list_pop(List *list, void **value)
{
    List *next;
    check(list, "empty list.");

    *value = list->value;
    next = list->next;

    free(list);
    return next;
error:
    *value = NULL;
    return list;
}
