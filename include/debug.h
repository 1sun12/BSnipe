#ifndef DEBUG_H
#define DEBUG_H

/**
 * @brief General headers:
 * - stdio.h    |   Standard I/O (printf, fprintf) used by the macros below
 * - stdlib.h   |   General utilities (EXIT_FAILURE) used by the macros below
 * @note These live here so the macros work no matter who includes debug.h first
 */
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Elite-C-Macro to output error message and then close the program
 * @note Returns from the calling function, so it is only usable inside `main`
 */
#define exit_with_error(msg) do {perror(msg); return(EXIT_FAILURE);} while(0)

/**
 * @brief Error check that checks existance of incoming `self` first
 * @note For functions returning void; see `does_exist_ret` for the rest
 */
#define does_exist(obj) do {if ((obj) == NULL) {fprintf(stderr, "\n[ERROR]:does_exist in %s\n", __func__); return;}} while(0)

/**
 * @brief Same as `does_exist`, but for functions that owe the caller a value back
 * @note A bare `return;` in a non-void function hands back whatever garbage was
 *       lying around, so those functions must say what they are returning
 */
#define does_exist_ret(obj, ret) do {if ((obj) == NULL) {fprintf(stderr, "\n[ERROR]:does_exist in %s\n", __func__); return (ret);}} while(0)

/**
 * @brief If 1, output additional debug messages (change to 0, remove extra messages)
 */
#define OUTPUT_DEBUG 0

/**
 * @brief Output a basic informational debug message
 */
#define OUTPUT_D_MSG(msg) do {if(OUTPUT_DEBUG) {printf("\n[INFO]:%s\n", msg);}} while(0)

#endif
