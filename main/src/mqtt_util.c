
#include "../include/mqtt_util.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../include/mqtt_parser.h"


int check(int status, const char* msg) {
    /* Error checking function */
    
    if (status < 0) {
        perror(msg);
        exit(EXIT_FAILURE);
        return -1;
    }
    return 0;
}


void push(vector *arr, void *item) {
    // Allocate enough size for the array
    if (arr->capacity == arr->size) {
        arr->capacity = (arr->capacity == 0) ? 4 : arr->capacity * 2;
        arr->data = realloc(arr->data, arr->capacity * arr->item_size);

        if (!arr->data) {
            perror("Realloc failed!");
            exit(EXIT_FAILURE);
        }
    }
    // Calculate next address the item should be pushed to
    void *target_address = (uint8_t *)arr->data + arr->size * arr->item_size;
    // Copy item_size bytes from item to target_address
    memcpy(target_address, item, arr->item_size);
    arr->size++;
}


void free_vec(vector *arr) {
    free(arr->data);
    arr->data = NULL;
    arr->capacity = 0;
    arr->size = 0;
    arr->item_size = 0;
}