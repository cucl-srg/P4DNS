#ifndef LINKED_LIST_TYPED_TEMPLATE_DECLARE_H_
#define LINKED_LIST_TYPED_TEMPLATE_DECLARE_H_


#include "../../types/types.h"
#include "linked_list.h"

#define declare_ch_llist(NAME,TYPE) \
\
struct ch_llist_##NAME;\
struct ch_llist_##NAME##_it_t;\
typedef struct ch_llist_##NAME ch_llist_##NAME##_t;\
typedef struct ch_llist_##NAME##_it_t ch_llist_##NAME##_it;\
\
struct ch_llist_##NAME##_it_t{ \
    ch_llist_node_t* _node; \
    TYPE* value;\
};\
\
\
struct ch_llist_##NAME{\
    ch_word count;  /*Return the actual number of elements in the llist*/ \
\
    ch_llist_##NAME##_it (*off)(ch_llist_##NAME##_t* this, ch_word idx); /* Return the element at a given offset, with bounds checking [WARN: This is slow in general] */\
\
    ch_llist_##NAME##_it (*first)(ch_llist_##NAME##_t* this); /*Get the first entry*/\
    ch_llist_##NAME##_it (*last)(ch_llist_##NAME##_t* this); /*Get the last entry*/\
    ch_llist_##NAME##_it (*end)(ch_llist_##NAME##_t* this); /*Get the end*/\
\
    void (*next)(ch_llist_##NAME##_t* this, ch_llist_##NAME##_it* it); /*Step forwards by one entry*/\
    void (*prev)(ch_llist_##NAME##_t* this, ch_llist_##NAME##_it*); /*Step backwards by one entry*/\
    void (*forward)(ch_llist_##NAME##_t* this, ch_llist_##NAME##_it* it, ch_word amount); /*Step forwards by amount*/\
    void (*back)(ch_llist_##NAME##_t* this, ch_llist_##NAME##_it* it, ch_word amount); /*Step backwards by amount*/\
\
    ch_llist_##NAME##_it (*push_front)(ch_llist_##NAME##_t* this, TYPE value); /* Put an element at the front of the linked list values,*/\
    ch_llist_##NAME##_it (*pop_front)(ch_llist_##NAME##_t* this);/* Push an element off the front of the linked list values,*/\
    ch_llist_##NAME##_it (*push_back)(ch_llist_##NAME##_t* this, TYPE value); /* Put an element at the back of the linked list values*/\
    ch_llist_##NAME##_it (*pop_back)(ch_llist_##NAME##_t* this); /* Push an element at the back of the linked list values*/\
\
    ch_llist_##NAME##_it* (*insert_after)(ch_llist_##NAME##_t* this, ch_llist_##NAME##_it* itr, TYPE value); /* Insert an element after the element given by ptr*/\
    ch_llist_##NAME##_it* (*insert_before)(ch_llist_##NAME##_t* this, ch_llist_##NAME##_it* it, TYPE value); /* Insert an element before the element giver by ptr*/\
    ch_llist_##NAME##_it (*remove_it)(ch_llist_##NAME##_t* this, ch_llist_##NAME##_it* itr); /*Remove the given ptr*/\
    ch_llist_##NAME##_it (*remove_all)(ch_llist_##NAME##_t* this, TYPE value); /*Remove the given ptr*/\
\
    void (*delete)(ch_llist_##NAME##_t* this); /*Free the resources associated with this llist, assumes that individual items have been freed*/\
\
    ch_llist_##NAME##_it (*push_back_carray)(ch_llist_##NAME##_t* this, const TYPE* carray, ch_word count); /*Push back count elements the C llist to the back llist-list*/\
\
    ch_word (*eq)(ch_llist_##NAME##_t* this, ch_llist_##NAME##_t* that); /*Check for equality*/\
    ch_llist_##NAME##_it (*find)(ch_llist_##NAME##_t* this, ch_llist_##NAME##_it* begin, ch_llist_##NAME##_it* end, TYPE value); /*find the given value using the comparator function*/\
    ch_llist_##NAME##_it (*find_first)(ch_llist_##NAME##_t* this, TYPE value); /*find the given value using the comparator function*/\
    ch_llist_##NAME##_it (*find_next)(ch_llist_##NAME##_t* this, ch_llist_##NAME##_it* begin, TYPE value); /*find the given value using the comparator function*/\
    ch_llist_##NAME##_it (*insert_inorder)(ch_llist_##NAME##_t* this, TYPE value); /* Insert an element before the element giver by ptr*/\
    ch_llist_##NAME##_it (*insert_carray_ordered)(ch_llist_##NAME##_t* this, const TYPE* carray, ch_word count); /*Insert count element in order*/\
    void (*sort)(ch_llist_##NAME##_t* this); /*sort into order given the comparator function*/\
\
     /* Members prefixed with "_" are nominally "private" Don't touch my privates!*/\
    ch_llist_t* _llist; /*Actual llist storage*/\
\
};\
\
\
ch_llist_##NAME##_t* ch_llist_##NAME##_new(ch_word(*cmp)(TYPE* lhs, TYPE* rhs) );


#define declare_ch_llist_cmp(NAME, TYPE) ch_word ch_llist_cmp_##NAME(TYPE* lhs, TYPE* rhs)


//**********************************************************************************************************************
//Shortcuts to make things more accessible
#define CH_LIST(NAME)  ch_llist_##NAME##_t
#define CH_LIST_IT(NAME)  ch_llist_##NAME##_it
#define CH_LIST_NEW(NAME, cmp) ch_llist_##NAME##_new(cmp )
#define CH_LIST_CMP(NAME) ch_llist_cmp_##NAME
#define CH_LIST_FOREACH(TYPE_NAME, LIST_NAME,IT_NAME) \
    for(CH_LIST_IT(TYPE_NAME) IT_NAME = LIST_NAME->first(LIST_NAME); IT_NAME.value; LIST_NAME->next(LIST_NAME,&IT_NAME))

#endif /*LINKED_LIST_TYPED_TEMPLATE_DECLARE_H_*/

