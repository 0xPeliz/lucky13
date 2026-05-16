#ifndef STATS_H
#define STATS_H

#include "../attacker/include/utility.h"

void init_python_environment();

void close_python_environment();

int analyze_single_byte(struct attack_result *result);

int analyze_double_bytes(struct first_attack_result *result);

#endif