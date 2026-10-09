#ifdef BYO_GATED_DEFECT
int gated(void)
{
    int *pointer = 0;
    return *pointer;
}
#endif

int ungated(void)
{
    return 0;
}
