/** @file
 * Copyright (c) 2023,2025, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#ifndef PAL_EL3_PRINT_H
#define PAL_EL3_PRINT_H

#if defined(__ASSEMBLER__)
# define   U(_x)        (_x)
# define  UL(_x)        (_x)
# define ULL(_x)        (_x)
# define   L(_x)        (_x)
# define  LL(_x)        (_x)
#else
# define  U_(_x)        (_x##U)
# define   U(_x)        U_(_x)
# define  UL(_x)        (_x##UL)
# define ULL(_x)        (_x##ULL)
# define   L(_x)        (_x##L)
# define  LL(_x)        (_x##LL)
#endif

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif

#define LOG_LEVEL_NONE                  U(0)
#define LOG_LEVEL_ERROR                 U(10)
#define LOG_LEVEL_NOTICE                U(20)
#define LOG_LEVEL_WARNING               U(30)
#define LOG_LEVEL_INFO                  U(40)
#define LOG_LEVEL_VERBOSE               U(50)


#ifndef __ASSEMBLER__

#include <cdefs.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

//#include <drivers/console.h>

/*
 * Define Log Markers corresponding to each log level which will
 * be embedded in the format string and is expected by tf_log() to determine
 * the log level.
 */
#define LOG_MARKER_ERROR                "\xa"   /* 10 */
#define LOG_MARKER_NOTICE               "\x14"  /* 20 */
#define LOG_MARKER_WARNING              "\x1e"  /* 30 */
#define LOG_MARKER_INFO                 "\x28"  /* 40 */
#define LOG_MARKER_VERBOSE              "\x32"  /* 50 */

/*
 * If the log output is too low then this macro is used in place of tf_log()
 * below. The intent is to get the compiler to evaluate the function call for
 * type checking and format specifier correctness but let it optimize it out.
 */
#define no_tf_log(fmt, ...)                             \
        do {                                            \
                if (false) {                            \
                        tf_log(fmt, ##__VA_ARGS__);     \
                }                                       \
        } while (false)

#if LOG_LEVEL >= LOG_LEVEL_ERROR
# define ERROR(...)     tf_log(LOG_MARKER_ERROR __VA_ARGS__)
# define ERROR_NL()     tf_log_newline(LOG_MARKER_ERROR)
#else
# define ERROR(...)     no_tf_log(LOG_MARKER_ERROR __VA_ARGS__)
# define ERROR_NL()
#endif

#if LOG_LEVEL >= LOG_LEVEL_NOTICE
# define NOTICE(...)    tf_log(LOG_MARKER_NOTICE __VA_ARGS__)
#else
# define NOTICE(...)    no_tf_log(LOG_MARKER_NOTICE __VA_ARGS__)
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARNING
# define WARN(...)      tf_log(LOG_MARKER_WARNING __VA_ARGS__)
#else
# define WARN(...)      no_tf_log(LOG_MARKER_WARNING __VA_ARGS__)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
# define INFO(...)      tf_log(LOG_MARKER_INFO __VA_ARGS__)
#else
# define INFO(...)      no_tf_log(LOG_MARKER_INFO __VA_ARGS__)
#endif

#if LOG_LEVEL >= LOG_LEVEL_VERBOSE
# define VERBOSE(...)   tf_log(LOG_MARKER_VERBOSE __VA_ARGS__)
#else
# define VERBOSE(...)   no_tf_log(LOG_MARKER_VERBOSE __VA_ARGS__)
#endif

#define __printflike(fmtarg, firstvararg) \
                __attribute__((__format__ (__printf__, fmtarg, firstvararg)))

extern void tf_log(const char *fmt, ...) __printflike(1, 2);
extern void tf_log_newline(const char log_fmt[2]);
extern void tf_log_set_max_level(unsigned int log_level);

#endif /* __ASSEMBLER__ */
#endif /* PAL_EL3_PRINT_H */

