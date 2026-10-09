#include "entry_local.h"

int entry_value(void)
{
    int *pointer = ENTRY_POINTER;
    return *pointer;
}
