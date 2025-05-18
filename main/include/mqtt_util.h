#ifndef mqtt_util_h
#define mqtt_util_h

#include <stdio.h>
#include <pthread.h>


typedef struct {
    void *data;
    size_t size;
    size_t capacity;
    size_t item_size;
} vector;


int check(int status, const char* msg);
void push(vector *arr, void *item);
void free_vec(vector *arr);


#endif