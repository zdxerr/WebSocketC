

#ifndef _list_h
#define _list_h

typedef struct ListNode ListNode;

struct ListNode {
    ListNode *next;
    ListNode *prev;
    void *value;
};

typedef struct List {
    int count;
    ListNode *first;
    ListNode *last;
} List;

#define list_count(A) ((A)->count)
#define list_first(A) ((A)->first != NULL ? (A)->first->value : NULL)
#define list_last(A) ((A)->last != NULL ? (A)->last->value : NULL)

#define LIST_FOREACH(L, S, M, V) \
ListNode *_node = NULL;\
ListNode *V = NULL;\
for(V = _node = L->S; _node != NULL; V = _node = _node->M)

void list_push(List *self, void *value);
void list_foreach(List *list, void (*function)(void *));
void list_foreach_destroy(List *list, void (*function)(void *));

void *list_remove_value(List *self, void *value);

#endif
