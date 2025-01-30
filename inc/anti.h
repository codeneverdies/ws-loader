#ifndef __ANTI_H
#define __ANTI_H

#include <stdbool.h>

#include "util.h"

// ./dj 'HOSTNAME'
#define WSL_TARGET 0x0

// Change sleep time for anti-sandbox
#define WSL_SLEEP_TIME 1000

extern bool wsl_check_ntg();

bool wsl_check_time(PCORE c);
bool wsl_check_hostname(PCORE c);
bool wsl_check_procs(PCORE c);
bool wsl_run_checks(PCORE c);

#endif // __ANTI_H