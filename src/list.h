
#ifndef _list_h
#define _list_h

#define list_value(list) ((list != NULL) ? list->value : NULL)
#define list_foreach(list, _N) for(_N = list;_N != NULL;_N = _N->next)

typedef struct List List;

struct List {
    List *next;
    void *value;
};

List *list_push(List *list, void *value);
List *list_pop(List *list, void **value);

#endif
