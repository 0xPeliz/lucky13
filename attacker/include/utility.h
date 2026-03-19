#ifndef UTILITY_H
#define UTILITY_H

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// Combinazione: Grassetto (1) + Verde (32)
#define BOLD_GREEN "\033[1;32m"

char *delete_char(char *str, char c);
void signals_handler(int signal); //function to handle the SIGINT signal, to restore the default network settings when the user presses CTRL+C
void print_application_data(unsigned char *application_data, unsigned int application_data_size);

#endif