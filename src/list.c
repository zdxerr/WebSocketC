
#include <stdlib.h>

#include "dbg.h"
#include "list.h"

int list_init(List *self)
{
    self->count = 0;
    self->first = NULL;
    self->last = NULL;
    return 1;
}

void list_destroy(List *self)
{
    LIST_FOREACH(self, first, next, cur)
    {
        if(cur->prev)
            free(cur->prev);
    }
    free(self->last);
}

void list_push(List *self, void *value)
{
    ListNode *node = calloc(1, sizeof(ListNode));
    check_mem(node);

    node->value = value;
    if(self->last == NULL)
    {
        self->first = node;
        self->last = node;
    }
    else
    {
        self->last->next = node;
        node->prev = self->last;
        self->last = node;
    }
    self->count++;

error:
    return;
}

void *list_pop(List *self)
{
    return NULL;
}

void *list_remove(List *self, ListNode *node)
{
    void *result = NULL;
    check(self->first && self->last, "List is empty.");
    check(node, "node can't be NULL");

    if(node == self->first && node == self->last)
    {
        self->first = NULL;
        self->last = NULL;
    }
    else if(node == self->first)
    {
        self->first = node->next;
        check(self->first != NULL, "Invalid self, somehow got a first that is NULL.");
        self->first->prev = NULL;
    }
    else if (node == self->last)
    {
        self->last = node->prev;
        check(self->last != NULL, "Invalid self, somehow got a next that is NULL.");
        self->last->next = NULL;
    }
    else
    {
        ListNode *after = node->next;
        ListNode *before = node->prev;
        after->prev = before;
        before->next = after;
    }

    self->count--;
    result = node->value;
    free(node);

error:
    return result;
}

ListNode *list_find(List *self, void *value)
{
    ListNode *node;
    for(node = self->first;node != NULL && node->value != value;node = node->next);
    return node;
}

void *list_remove_value(List *self, void *value)
{
    ListNode *node = list_find(self, value);
    return list_remove(self, node);
}

void list_foreach(List *list, void (*function)(void *))
{
    LIST_FOREACH(list, first, next, cur)
    {
        if(function)
            function(cur->value);
    }
}

void list_foreach_destroy(List *list, void (*function)(void *))
{
    list_foreach(list, function);
    list_destroy(list);
}
