#ifndef mqtt_util_h
#define mqtt_util_h

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>


typedef struct {
    void *data;
    size_t size;
    size_t capacity;
    size_t item_size;
} vector;


typedef struct {
    char *topic;
    uint8_t qos;
} subscription;


typedef struct { 
    char *client_id;
    int client_socket;
    subscription *subscriptions;    // list of subscriptions
    int *unaknowledged_message_ids;
    bool clean_session;
} session_state;


int check(int status, const char* msg);
void push(vector *arr, void *item);
void free_vec(vector *arr);


#endif