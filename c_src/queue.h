// This file is part of Emonk released under the MIT license. 
// See the LICENSE file for more information.

/* adapted by: Maas-Maarten Zeeman <mmzeeman@xs4all.nl */
/* further adapted by: Felix Kiunke <dev@fkiunke.de>
   okay, I only changed ESQLITE3_QUEUE_H TO ESQLCIPHER_QUEUE_H actually... */

#ifndef ESQLCIPHER_QUEUE_H
#define ESQLCIPHER_QUEUE_H

#include "erl_nif.h"

typedef struct queue_t queue;

queue * queue_create();
void queue_destroy(queue *queue);

int queue_has_item(queue *queue);

int queue_push(queue *queue, void* item);
void* queue_pop(queue *queue);

int queue_send(queue *queue, void* item);
void* queue_receive(queue *);

#endif 
