/*
    The target memory information array (storage of matches).

    Copyright (C) 2009 Eli Dupree  <elidupree(a)charter.net>
    Copyright (C) 2010 WANG Lu  <coolwanglu(a)gmail.com>
    Copyright (C) 2015 Sebastian Parschauer <s.parschauer@gmx.de>

    This file is part of libscanmem.

    This library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this library.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef TARGETMEM_H
#define TARGETMEM_H

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <ctype.h>

#include "value.h"
#include "show_message.h"

/* Public structs */

/* Single match struct */
typedef struct
{
    uint8_t old_value;
    match_flags match_info;
} old_value_and_match_info;

/* Array that contains a consecutive (in memory) sequence of matches (= swath).
   - the first_byte_in_child pointer refers to locations in the child,
     it cannot be followed except using ptrace()
   - the number_of_bytes refers to the number of bytes in the child
     process's memory that are covered, not the number of bytes the struct
     takes up. It's the length of data. */
typedef struct __attribute__((packed, aligned(sizeof(old_value_and_match_info))))
{
    void *first_byte_in_child;
    size_t number_of_bytes;
    old_value_and_match_info data[0];
} matches_and_old_values_swath;

/* Master matches array, smartly resized, contains swaths.
   Both `bytes` values refer to real struct bytes this time. */
typedef struct
{
    size_t bytes_allocated;
    size_t max_needed_bytes;
    matches_and_old_values_swath swaths[0];
} matches_and_old_values_array;

/* Location of a match in a matches_and_old_values_array */
typedef struct
{
    matches_and_old_values_swath *swath;
    size_t index;
} match_location;


/* Public functions */

matches_and_old_values_array *
allocate_array(matches_and_old_values_array *array, size_t max_bytes)
{
    /* make enough space for the array header and a null first swath */
    size_t bytes_to_allocate =
            sizeof(matches_and_old_values_array) +
            sizeof(matches_and_old_values_swath);
    
    if (!(array = realloc(array, bytes_to_allocate)))
        return NULL;
    
    array->bytes_allocated = bytes_to_allocate;
    array->max_needed_bytes = max_bytes;
    
    return array;
}

matches_and_old_values_array *
null_terminate(matches_and_old_values_array *array,
               matches_and_old_values_swath *swath)
{
    size_t bytes_needed;
    
    if (swath->number_of_bytes == 0) {
        assert(swath->first_byte_in_child == NULL);
        
    } else {
        swath = local_address_beyond_last_element(swath);
        array = allocate_enough_to_reach(array, ((void *) swath) +
                                                sizeof(matches_and_old_values_swath),
                                         swath);
        swath->first_byte_in_child = NULL;
        swath->number_of_bytes = 0;
    }
    
    bytes_needed = ((void *) swath + sizeof(matches_and_old_values_swath) -
                    (void *) array);
    
    if (bytes_needed < array->bytes_allocated) {
        /* reduce array to its final size */
        if (!(array = realloc(array, bytes_needed)))
            return NULL;
        
        array->bytes_allocated = bytes_needed;
    }
    
    return array;
}

/* for printable text representation */
void data_to_printable_string(char *buf, int buf_length,
                              matches_and_old_values_swath *swath,
                              size_t index, int string_length)
{
    long swath_length = swath->number_of_bytes - index;
    /* TODO: what if length is too large ? */
    long max_length = (swath_length >= string_length) ? string_length : swath_length;
    int i;
    
    for(i = 0; i < max_length; ++i) {
        uint8_t byte = swath->data[index + i].old_value;
        buf[i] = isprint(byte) ? byte : '.';
    }
    buf[i] = 0; /* null-terminate */
}

/* for bytearray representation */
void data_to_bytearray_text(char *buf, int buf_length,
                            matches_and_old_values_swath *swath,
                            size_t index, int bytearray_length)
{
    int i;
    int bytes_used = 0;
    long swath_length = swath->number_of_bytes - index;
    
    /* TODO: what if length is too large ? */
    long max_length = (swath_length >= bytearray_length) ?
                      bytearray_length : swath_length;
    
    for(i = 0; i < max_length; ++i) {
        uint8_t byte = swath->data[index + i].old_value;
        
        /* TODO: check error here */
        snprintf(buf + bytes_used, buf_length - bytes_used,
                 (i < max_length - 1) ? "%02x " : "%02x", byte);
        bytes_used += 3;
    }
}

match_location
nth_match(matches_and_old_values_array *matches, size_t n)
{
    size_t i = 0;
    matches_and_old_values_swath *reading_swath_index;
    size_t reading_iterator = 0;
    
    assert(matches);
    reading_swath_index = matches->swaths;
    
    while (reading_swath_index->first_byte_in_child) {
        /* only actual matches are considered */
        if (reading_swath_index->data[reading_iterator].match_info != flags_empty) {
            
            if (i == n)
                return (match_location) { reading_swath_index, reading_iterator };
            
            ++i;
        }
        
        /* go on to the next one... */
        ++reading_iterator;
        if (reading_iterator >= reading_swath_index->number_of_bytes) {
            reading_swath_index =
                    local_address_beyond_last_element(reading_swath_index);
            
            reading_iterator = 0;
        }
    }
    
    /* I guess this is not a valid match-id */
    return (match_location) { NULL, 0 };
}

/* deletes matches in [start, end) and resizes the matches array */
matches_and_old_values_array *
delete_in_address_range(matches_and_old_values_array *array,
                        unsigned long *num_matches,
                        void *start_address, void *end_address)
{
    assert(array);
    
    size_t reading_iterator = 0;
    matches_and_old_values_swath *reading_swath_index = array->swaths;
    
    matches_and_old_values_swath reading_swath = *reading_swath_index;
    
    matches_and_old_values_swath *writing_swath_index = array->swaths;
    
    writing_swath_index->first_byte_in_child = NULL;
    writing_swath_index->number_of_bytes = 0;
    
    *num_matches = 0;
    
    while (reading_swath.first_byte_in_child) {
        void *address = reading_swath.first_byte_in_child + reading_iterator;
        
        if (address < start_address || address >= end_address) {
            old_value_and_match_info old_byte;
            
            old_byte = reading_swath_index->data[reading_iterator];
            
            /* Still a candidate. Write data.
                (We can get away with overwriting in the same array because
                 it is guaranteed to take up the same number of bytes or fewer,
                 and because we copied out the reading swath metadata already.)
                (We can get away with assuming that the pointers will stay
                 valid, because as we never add more data to the array than
                 there was before, it will not reallocate.) */
            writing_swath_index = add_element(&array,
                                              writing_swath_index, address,
                                              old_byte.old_value, old_byte.match_info);
            
            /* actual matches are recorded */
            if (old_byte.match_info != flags_empty)
                ++(*num_matches);
        }
        
        /* go on to the next one... */
        ++reading_iterator;
        if (reading_iterator >= reading_swath.number_of_bytes) {
            
            reading_swath_index = (matches_and_old_values_swath *)
                    (&reading_swath_index->data[reading_swath.number_of_bytes]);
            
            reading_swath = *reading_swath_index;
            
            reading_iterator = 0;
        }
    }
    
    return null_terminate(array, writing_swath_index);
}


static inline
size_t
index_of_last_element(matches_and_old_values_swath *swath)
{
    return swath->number_of_bytes - 1;
}

static inline
void *
remote_address_of_nth_element(matches_and_old_values_swath *swath, size_t n)
{
    return swath->first_byte_in_child + n;
}

static inline
void *
remote_address_of_last_element(matches_and_old_values_swath *swath)
{
    return (remote_address_of_nth_element(swath, index_of_last_element(swath)));
}

static inline
void *
local_address_beyond_nth_element(matches_and_old_values_swath *swath, size_t n)
{
    return &(swath->data[n + 1]);
}

static inline
void *
local_address_beyond_last_element(matches_and_old_values_swath *swath)
{
    return (local_address_beyond_nth_element(swath, index_of_last_element(swath)));
}

static inline matches_and_old_values_array *
allocate_enough_to_reach(matches_and_old_values_array *array,
                         void *last_byte_to_reach_plus_one,
                         matches_and_old_values_swath **swath_pointer_to_correct)
{
    size_t bytes_needed = last_byte_to_reach_plus_one - (void *) array;
    
    if (bytes_needed <= array->bytes_allocated)
        return array;
    
    matches_and_old_values_array *original_location = array;
    
    /* allocate twice as much each time,
       so we don't have to do it too often */
    size_t bytes_to_allocate = array->bytes_allocated;
    while (bytes_to_allocate < bytes_needed)
        bytes_to_allocate *= 2;
    
    show_debug("to_allocate %ld, max %ld\n", bytes_to_allocate,
               array->max_needed_bytes);
    
    /* sometimes we know an absolute max that we will need */
    if (array->max_needed_bytes < bytes_to_allocate) {
        assert(array->max_needed_bytes >= bytes_needed);
        bytes_to_allocate = array->max_needed_bytes;
    }
    
    if (!(array = realloc(array, bytes_to_allocate)))
        return NULL;
    
    array->bytes_allocated = bytes_to_allocate;
    
    /* Put the swath pointer back where it should be, if needed.
       We cast everything to void pointers in this line to make
       sure the math works out. */
    if (swath_pointer_to_correct) {
        *swath_pointer_to_correct = (matches_and_old_values_swath *)
                (((void *) (*swath_pointer_to_correct)) +
                 ((void *) array - (void *) original_location));
    }
    
    return array;
}

/* returns a pointer to the swath to which the element was added -
   i.e. the last swath in the array after the operation */
static inline
matches_and_old_values_swath *
add_element(matches_and_old_values_array **array,
            matches_and_old_values_swath *swath,
            void *remote_address,
            uint8_t new_byte,
            match_flags new_flags)
{
    if (swath->number_of_bytes == 0) {
        assert(swath->first_byte_in_child == NULL);
        
        /* we have to overwrite this as a new swath */
        *array = allocate_enough_to_reach(*array,
                                          ((void *) swath
                                           + sizeof(matches_and_old_values_swath)
                                           + sizeof(old_value_and_match_info)),
                                          &swath);
        
        swath->first_byte_in_child = remote_address;
        
    } else {
        size_t local_index_excess =
                remote_address - remote_address_of_last_element(swath);
        
        size_t local_address_excess =
                local_index_excess * sizeof(old_value_and_match_info);
        
        size_t needed_size_for_a_new_swath =
                sizeof(matches_and_old_values_swath) + sizeof(old_value_and_match_info);
        
        if (local_address_excess >= needed_size_for_a_new_swath) {
            /* It is more memory-efficient to start a new swath.
             * The equal case is decided for a new swath, so that
             * later we don't needlessly iterate through a bunch
             * of empty values */
            *array = allocate_enough_to_reach(*array,
                                              local_address_beyond_last_element(swath) +
                                              needed_size_for_a_new_swath, &swath);
            
            swath = local_address_beyond_last_element(swath);
            swath->first_byte_in_child = remote_address;
            swath->number_of_bytes = 0;
            
        } else {
            /* It is more memory-efficient to write over the intervening
               space with null values */
            *array = allocate_enough_to_reach(*array,
                                              local_address_beyond_last_element(swath) +
                                              local_address_excess, &swath);
            
            switch (local_index_excess) {
                case 1:
                    /* do nothing, the new value is right after the old */
                    break;
                case 2:
                    memset(local_address_beyond_last_element(swath),
                           0,
                           sizeof(old_value_and_match_info));
                    break;
                default:
                    /* slow due to unknown size to be zeroed */
                    memset(local_address_beyond_last_element(swath),
                           0,
                           local_address_excess - sizeof(old_value_and_match_info));
                    break;
            }
            swath->number_of_bytes += local_index_excess - 1;
        }
    }
    
    /* add me */
    old_value_and_match_info *dataptr = local_address_beyond_last_element(swath);
    dataptr->old_value = new_byte;
    dataptr->match_info = new_flags;
    swath->number_of_bytes++;
    
    return swath;
}

/* only at most sizeof(int64_t) bytes will be read,
   if more bytes are needed (e.g. bytearray),
   read them separately (for performance) */
static inline value_t
data_to_val_aux(const matches_and_old_values_swath *swath,
                size_t index, size_t swath_length)
{
    unsigned int i;
    value_t val;
    size_t max_bytes = swath_length - index;
    
    /* Init all possible flags in a single go.
     * Also init length to the maximum possible value */
    val.flags = flags_max;
    
    /* NOTE: This does the right thing for VLT because the flags are in
     * the same order as the number representation (for both endians), so
     * that the zeroing of a flag does not change useful bits of `length`. */
    if (max_bytes > 8)
        max_bytes = 8;
    if (max_bytes < 8)
        val.flags &= ~flags_64b;
    if (max_bytes < 4)
        val.flags &= ~flags_32b;
    if (max_bytes < 2)
        val.flags &= ~flags_16b;
    if (max_bytes < 1)
        val.flags = flags_empty;
    
    for(i = 0; i < max_bytes; ++i) {
        /* Both uint8_t, no explicit casting needed */
        val.bytes[i] = swath->data[index + i].old_value;
    }
    
    /* Truncate to the old flags, which are stored with the first matched byte */
    val.flags &= swath->data[index].match_info;
    
    return val;
}

static inline value_t
data_to_val(const matches_and_old_values_swath *swath, size_t index)
{
    return data_to_val_aux(swath, index, swath->number_of_bytes);
}

#endif /* TARGETMEM_H */
