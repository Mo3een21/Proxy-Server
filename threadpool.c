
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "threadpool.h"

threadpool* create_threadpool(int num_threads_in_pool) {
    // Input sanity check
    if (num_threads_in_pool <= 0 || num_threads_in_pool > MAXT_IN_POOL) {
        printf( "Error: Invalid number of threads for thread pool.\n");
        return NULL;
    }

    // Allocate memory for the threadpool structure
    threadpool* tp = (threadpool*)malloc(sizeof(threadpool));
    if (tp == NULL) {
        perror("Error: Memory allocation failed for threadpool");
        return NULL;
    }

    // Initialize threadpool structure members
    tp->num_threads = num_threads_in_pool;
    tp->qsize = 0;
    tp->qhead = NULL;
    tp->qtail = NULL;
    tp->shutdown = 0;
    tp->dont_accept = 0;

    // Initialize mutex and conditional variables
    if (pthread_mutex_init(&tp->qlock, NULL) != 0) {
        perror("Error: Mutex initialization failed");
        free(tp);
        return NULL;
    }
    if (pthread_cond_init(&tp->q_not_empty, NULL) != 0 || pthread_cond_init(&tp->q_empty, NULL) != 0) {
        perror("Error: Conditional variable initialization failed");
        pthread_mutex_destroy(&tp->qlock);
        free(tp);
        return NULL;
    }

    // Allocate memory for threads
    tp->threads = (pthread_t*)malloc(num_threads_in_pool * sizeof(pthread_t));
    if (tp->threads == NULL) {
        perror("Error: Memory allocation failed for threads");
        pthread_mutex_destroy(&tp->qlock);
        pthread_cond_destroy(&tp->q_not_empty);
        pthread_cond_destroy(&tp->q_empty);
        free(tp);
        return NULL;
    }

    // Create threads
    for (int i = 0; i < num_threads_in_pool; i++) {
        if (pthread_create(&tp->threads[i], NULL, do_work, (void*)tp) != 0) {
            perror("Error: Failed to create thread");
            // Cleanup and return NULL
            for (int j = 0; j < i; j++) {
                pthread_cancel(tp->threads[j]);
            }
            free(tp->threads);
            pthread_mutex_destroy(&tp->qlock);
            pthread_cond_destroy(&tp->q_not_empty);
            pthread_cond_destroy(&tp->q_empty);
            free(tp);
            return NULL;
        }
    }

    return tp;
}
work_t* dequeue(threadpool* tp) {
    // Check if the queue is empty
    if (tp->qsize == 0) {
        return NULL; // Return NULL if the queue is empty
    }

    // Get the first work item from the queue
    work_t* work = tp->qhead;

    // Update the queue head to point to the next item
    tp->qhead = tp->qhead->next;

    // If the queue becomes empty after dequeuing
    if (tp->qhead == NULL) {
        tp->qtail = NULL; // Update the tail pointer to NULL
    }

    // Decrement the queue size
    tp->qsize--;

    return work;
}


void* do_work(void* p) {
    threadpool* tp = (threadpool*)p;
    while (true) {
        // Lock the mutex
        pthread_mutex_lock(&tp->qlock);

        // Check if the queue is empty and shutdown flag is not set
        while (tp->qsize == 0 && !tp->shutdown) {
            // Wait for the queue to become non-empty
            pthread_cond_wait(&tp->q_not_empty, &tp->qlock);
        }

        // If the shutdown flag is set, unlock the mutex and exit the thread
        if (tp->shutdown) {
            pthread_mutex_unlock(&tp->qlock);
            pthread_exit(NULL);
        }

        // Dequeue the first work item from the queue
        work_t* work = dequeue(tp); // Pass the threadpool pointer tp to the dequeue function

        // If we are not accepting any more jobs and the queue is empty,
        // wake up the thread waiting at the destroy function
        if (tp->qsize == 0 && tp->dont_accept) {
            pthread_cond_signal(&tp->q_empty);
        }

        // Unlock the mutex
        pthread_mutex_unlock(&tp->qlock);

        // Execute the job
        work->routine(work->arg);
        free(work);
    }

}


void destroy_threadpool(threadpool* destroyme) {
    // Lock the mutex
    pthread_mutex_lock(&destroyme->qlock);

    // Set that the threadpool destruction has begun
    destroyme->dont_accept = 1;

    // If there are still jobs in the queue, then wait
    while (destroyme->qsize > 0) {
        pthread_cond_wait(&destroyme->q_empty, &destroyme->qlock);
    }

    // Set the shutdown flag since there are no more jobs in the queue
    destroyme->shutdown = 1;

    // Wakeup all threads that wait while the qsize == 0
    pthread_cond_broadcast(&destroyme->q_not_empty);

    // Unlock the mutex
    pthread_mutex_unlock(&destroyme->qlock);

    // Wait for the exits of the threads
    int i = 0;
    while(i < destroyme->num_threads) {
        if (pthread_join(destroyme->threads[i], NULL) != 0) {
            perror("pthread_join error");
            return;
        }

        i++;
    }
    free(destroyme->threads);
    pthread_mutex_destroy(&(destroyme->qlock));
    pthread_cond_destroy(&(destroyme->q_not_empty));
    pthread_cond_destroy(&(destroyme->q_empty));
    free(destroyme);
}

void enqueue(threadpool* from_me, work_t* work) {
    // If the queue is empty, set both head and tail to the new work item
    if (from_me->qhead == NULL) {
        from_me->qhead = work;
        from_me->qtail = work;
    } else {
        // Otherwise, add the new work item to the end of the queue
        from_me->qtail->next = work;
        from_me->qtail = work;
    }
    // Ensure the new work item's next pointer is NULL
    work->next = NULL;
}

void dispatch(threadpool* from_me, dispatch_fn dispatch_to_here, void *arg) {
    // Lock the mutex
    pthread_mutex_lock(&from_me->qlock);

    // If the threadpool is in the destruction process, return
    if (from_me->dont_accept == 1) {
        pthread_mutex_unlock(&from_me->qlock);
        return;
    }

    // Create a new job and append it to the queue
    work_t* work = (work_t*)malloc(sizeof(work_t));
    if (work == NULL) {
        perror("Error: Memory allocation failed for work");
        pthread_mutex_unlock(&from_me->qlock);
        return;
    }
    work->routine = dispatch_to_here;
    work->arg = arg;
    enqueue(from_me, work); // Assuming enqueue function is implemented

    // Update the queue size
    from_me->qsize++;

    // Signal that the queue is not empty
    pthread_cond_signal(&from_me->q_not_empty);

    // Unlock the mutex
    pthread_mutex_unlock(&from_me->qlock);
}

void* Task(void* arg)
{
    int i = 0;
    while(i<1000) {
        printf("THREAD_ID: %lx\n", pthread_self());
        i++;
    }
//    printf("***\n");//to let us know that a new thread is being printed
    usleep(100000);
    // Sleep for 100 milliseconds (100,000 microseconds)

    return NULL;
}
typedef struct {
    struct sockaddr_in sockinfo;
    int sockfd;
} CLIENT_INFO, *PCLIENT_INFO;
