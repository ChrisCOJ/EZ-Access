#ifndef mqtt_util_h
#define mqtt_util_h

#include <stddef.h> 


/**
 * Dynamic array structure
 */
typedef struct {
    void *data;        /**< Pointer to the array data */
    size_t size;       /**< Current number of elements */
    size_t capacity;   /**< Total allocated capacity */
    size_t item_size;  /**< Size of each item in bytes */
} vector;

/**
 * Add a new item to the end of the vector
 * @param arr Pointer to the vector
 * @param item Pointer to the item to insert
 */
void push(vector *arr, void *item);

/**
 * Remove an element at a specified index
 * @param vec Pointer to the vector
 * @param index Index of the element to remove
 */
void vec_remove(vector *vec, int index);

/**
 * Free the memory allocated for the vector
 * @param arr Pointer to the vector
 */
void free_vec(vector *arr);


#endif