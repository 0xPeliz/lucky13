#ifndef UTILITY_H
#define UTILITY_H

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define BOLD_GREEN "\033[1;32m"

typedef unsigned char Byte;

char *delete_char(char *str, char c);
void signals_handler(int signal); //function to handle the SIGINT signal, to restore the default network settings when the user presses CTRL+C
void print_application_data(Byte *application_data, unsigned int application_data_size);
void catch_signals();
bool check_data_length(Byte *data, unsigned int data_len);
void print_data_blocks(Byte *data, unsigned int data_len);
void print_blocks(Byte *data, unsigned int data_len);
Byte *xor_block(Byte *block1, Byte *block2, unsigned int len);

#endif