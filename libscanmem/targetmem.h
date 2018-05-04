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
    uint16_t flags;
} old_value_and_match_info;

/* Array that contains a consecutive (in memory) sequence of matches (= swath).
   - the first_byte_in_child pointer refers to locations in the child,
     it cannot be followed except using ptrace()
   - the number_of_bytes refers to the number of bytes in the child
     process's memory that are covered, not the number of bytes the struct
     takes up. It's the length of data. */
typedef struct __attribute__((packed, aligned(sizeof(old_value_and_match_info))))
{
    uintptr_t first_byte_in_child;
    size_t number_of_bytes;
    old_value_and_match_info data[0];
} swath_t;

/* Master matches array, smartly resized, contains swaths.
   Both `bytes` values refer to real struct bytes this time. */
typedef struct
{
    size_t bytes_allocated;
    size_t max_needed_bytes;
    swath_t swaths[0];
} matches_t;

/* Location of a match in a matches_t */
typedef struct
{
    swath_t *swath;
    size_t index;
} match_location;


/* Public functions */

static inline
size_t
swath__index_of_last_element(swath_t *swath)
{
    return swath->number_of_bytes - 1;
}


static inline
uintptr_t
swath__remote_address_of_nth_element(swath_t *swath,
                                     size_t n)
{
    return swath->first_byte_in_child + n;
}


static inline
uintptr_t
swath__remote_address_of_last_element(swath_t *swath)
{
    return (swath__remote_address_of_nth_element(swath, swath__index_of_last_element(swath)));
}


static inline
void *
swath__local_address_beyond_nth_element(swath_t *swath,
                                        size_t n)
{
    return &(swath->data[n + 1]);
}


static inline
void *
swath__local_address_beyond_last_element(swath_t *swath)
{
    return swath__local_address_beyond_nth_element(swath, swath__index_of_last_element(swath));
}


static inline
matches_t *
matches__allocate_enough_to_reach(matches_t *matches,
                                  void *last_byte_to_reach_plus_one,
                                  swath_t **swath_pointer_to_correct)
{
    size_t bytes_needed = (char *) last_byte_to_reach_plus_one - (char *) matches;
    
    if (bytes_needed <= matches->bytes_allocated)
        return matches;
    
    matches_t *original_location = matches;
    
    /* allocate twice as much each time,
       so we don't have to do it too often */
    size_t bytes_to_allocate = matches->bytes_allocated;
    while (bytes_to_allocate < bytes_needed)
        bytes_to_allocate *= 2;
    
    show_debug("to_allocate %ld, max %ld\n",
               bytes_to_allocate,
               matches->max_needed_bytes);
    
    /* sometimes we know an absolute max that we will need */
    if (matches->max_needed_bytes < bytes_to_allocate) {
        assert(matches->max_needed_bytes >= bytes_needed);
        bytes_to_allocate = matches->max_needed_bytes;
    }
    
    if ((matches = (matches_t *)(realloc(matches, bytes_to_allocate))) == NULL)
        return NULL;
    
    matches->bytes_allocated = bytes_to_allocate;
    
    /* Put the swath pointer back where it should be, if needed.
       We cast everything to void pointers in this line to make
       sure the math works out. */
    if (swath_pointer_to_correct) {
        *swath_pointer_to_correct = (swath_t *)
                (((char *) (*swath_pointer_to_correct))
                 + ((char *) matches - (char *) original_location));
    }
    
    return matches;
}


/* returns a pointer to the swath to which the element was added -
   i.e. the last swath in the array after the operation */
static inline
swath_t *
matches__add_element(matches_t **array,
                     swath_t *swath,
                     uintptr_t remote_address,
                     uint8_t new_byte,
                     uint16_t new_flags)
{
    if (swath->number_of_bytes == 0) {
        assert(swath->first_byte_in_child == 0);
        
        /* we have to overwrite this as a new swath */
        *array = matches__allocate_enough_to_reach(*array,
                                                   ((char *) swath
                                                    + sizeof(swath_t)
                                                    + sizeof(old_value_and_match_info)),
                                                   &swath);
        
        swath->first_byte_in_child = remote_address;
    }
    else {
        size_t local_index_excess =
                remote_address - swath__remote_address_of_last_element(swath);
        
        size_t local_address_excess =
                local_index_excess * sizeof(old_value_and_match_info);
        
        size_t needed_size_for_a_new_swath =
                sizeof(swath_t) + sizeof(old_value_and_match_info);
        
        if (local_address_excess >= needed_size_for_a_new_swath) {
            /* It is more memory-efficient to start a new swath.
             * The equal case is decided for a new swath, so that
             * later we don't needlessly iterate through a bunch
             * of empty values */
            *array = matches__allocate_enough_to_reach(*array,
                                                       swath__local_address_beyond_last_element(swath)
                                                       + needed_size_for_a_new_swath,
                                                       &swath);
            
            swath = swath__local_address_beyond_last_element(swath);
            swath->first_byte_in_child = remote_address;
            swath->number_of_bytes = 0;
        }
        else {
            /* It is more memory-efficient to write over the intervening
               space with null values */
            *array = matches__allocate_enough_to_reach(*array,
                                                       swath__local_address_beyond_last_element(swath)
                                                       + local_address_excess,
                                                       &swath);
            
            switch (local_index_excess) {
                case 1:
                    /* do nothing, the new value is right after the old */
                    break;
                case 2:
                    memset(swath__local_address_beyond_last_element(swath),
                           0,
                           sizeof(old_value_and_match_info));
                    break;
                default:
                    /* slow due to unknown size to be zeroed */
                    memset(swath__local_address_beyond_last_element(swath),
                           0,
                           local_address_excess - sizeof(old_value_and_match_info));
                    break;
            }
            swath->number_of_bytes += local_index_excess - 1;
        }
    }
    
    /* add me */
    old_value_and_match_info *dataptr = swath__local_address_beyond_last_element(swath);
    dataptr->old_value = new_byte;
    dataptr->flags = new_flags;
    swath->number_of_bytes++;
    
    return swath;
}

/** Если первый аргумент NULL то работает как аллокатор, а не реаллокатор */
static inline
matches_t *
matches__allocate_array(matches_t *matches,
                        size_t max_bytes)
{
    /* make enough space for the matches header and a null first swath */
    size_t bytes_to_allocate =
            sizeof(matches_t) 
            + sizeof(swath_t);
    
    if ((matches = (matches_t *)(realloc(matches, bytes_to_allocate))) == NULL)
        return NULL;
    
    matches->bytes_allocated = bytes_to_allocate;
    matches->max_needed_bytes = max_bytes;
    
    return matches;
}

/** Всё очевидно */
static inline
matches_t *
matches__null_terminate(matches_t *matches,
                        swath_t *swath)
{
    size_t bytes_needed;
    
    if (swath->number_of_bytes == 0) {
        assert(swath->first_byte_in_child == 0);
    } else {
        swath = swath__local_address_beyond_last_element(swath);
        matches = matches__allocate_enough_to_reach(matches,
                                                    (char *) (swath) + sizeof(swath_t),
                                                    &swath);
        swath->first_byte_in_child = 0;
        swath->number_of_bytes = 0;
    }
    
    bytes_needed = (char *) swath
                   + sizeof(swath_t)
                   - (char *) matches;
    
    if (bytes_needed < matches->bytes_allocated) {
        /* reduce matches to its final size */
        if ((matches = (matches_t *) (realloc(matches, bytes_needed))) == NULL)
            return NULL;
        
        matches->bytes_allocated = bytes_needed;
    }
    
    return matches;
}

static inline
match_location
matches__nth_match(matches_t *matches,
                   size_t n)
{
    size_t i = 0;
    swath_t *reading_swath_index;
    size_t reading_iterator = 0;
    
    assert(matches);
    reading_swath_index = matches->swaths;
    
    while (reading_swath_index->first_byte_in_child) {
        /* only actual matches are considered */
        if (reading_swath_index->data[reading_iterator].flags != flags_empty) {
            
            if (i == n)
                return (match_location) { reading_swath_index, reading_iterator };
            
            i++;
        }
        
        /* go on to the next one... */
        reading_iterator++;
        if (reading_iterator >= reading_swath_index->number_of_bytes) {
            reading_swath_index =
                    swath__local_address_beyond_last_element(reading_swath_index);
            
            reading_iterator = 0;
        }
    }
    
    /* I guess this is not a valid match-id */
    return (match_location) { NULL, 0 };
}



/* deletes matches in [start, end) and resizes the matches array */
static inline
matches_t *
matches__delete_in_address_range(matches_t *matches,
                                 unsigned long *num_matches,
                                 uintptr_t start_address,
                                 uintptr_t end_address)
{
    assert(matches);
    
    size_t reading_iterator = 0;
    swath_t *reading_swath_index = matches->swaths;
    
    swath_t reading_swath = *reading_swath_index;
    
    swath_t *writing_swath_index = matches->swaths;
    
    writing_swath_index->first_byte_in_child = 0;
    writing_swath_index->number_of_bytes = 0;
    
    *num_matches = 0;
    
    while (reading_swath.first_byte_in_child) {
        uintptr_t address = reading_swath.first_byte_in_child + reading_iterator;
        
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
            writing_swath_index = matches__add_element(&matches,
                                                       writing_swath_index,
                                                       address,
                                                       old_byte.old_value,
                                                       old_byte.flags);
            
            /* actual matches are recorded */
            if (old_byte.flags != flags_empty)
                (*num_matches)++;
        }
        
        /* go on to the next one... */
        reading_iterator++;
        if (reading_iterator >= reading_swath.number_of_bytes) {
            
            reading_swath_index = (swath_t *)
                    (&reading_swath_index->data[reading_swath.number_of_bytes]);
            
            reading_swath = *reading_swath_index;
            
            reading_iterator = 0;
        }
    }
    
    return matches__null_terminate(matches, writing_swath_index);
}


/* for printable text representation */
static inline
void data_to_printable_string(char *buf,
                              int buf_length,
                              swath_t *swath,
                              size_t index,
                              int string_length)
{
    long swath_length = swath->number_of_bytes - index;
    /* TODO: what if length is too large ? */
    long max_length = (swath_length >= string_length) ? string_length : swath_length;
    int i;
    
    for(i = 0; i < max_length; i++) {
        uint8_t byte = swath->data[index + i].old_value;
        buf[i] = isprint(byte) ? byte : '.';
    }
    buf[i] = 0; /* null-terminate */
}


/* for bytearray representation */
static inline
void data_to_bytearray_text(char *buf,
                            int buf_length,
                            swath_t *swath,
                            size_t index,
                            int bytearray_length)
{
    int i;
    int bytes_used = 0;
    long swath_length = swath->number_of_bytes - index;
    
    /* TODO: what if length is too large ? */
    long max_length = (swath_length >= bytearray_length) ?
                      bytearray_length : swath_length;
    
    for(i = 0; i < max_length; i++) {
        uint8_t byte = swath->data[index + i].old_value;
        
        /* TODO: check error here */
        snprintf(buf + bytes_used, buf_length - bytes_used,
                 (i < max_length - 1) ? "%02x " : "%02x", byte);
        bytes_used += 3;
    }
}


/* only at most sizeof(int64_t) bytes will be read,
   if more bytes are needed (e.g. bytearray),
   read them separately (for performance) */
static inline value_t
data_to_val_aux(const swath_t *swath,
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
    
    for(i = 0; i < max_bytes; i++) {
        /* Both uint8_t, no explicit casting needed */
        val.bytes[i] = swath->data[index + i].old_value;
    }
    
    /* Truncate to the old flags, which are stored with the first matched byte */
    val.flags &= swath->data[index].flags;
    
    return val;
}

static inline value_t
data_to_val(const swath_t *swath, size_t index)
{
    return data_to_val_aux(swath, index, swath->number_of_bytes);
}

#endif /* TARGETMEM_H */
