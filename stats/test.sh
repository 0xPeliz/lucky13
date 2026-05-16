gcc test_stats.c stats.c -o test_integration \
    $(python3-config --cflags --embed) \
    $(python3-config --ldflags --embed)