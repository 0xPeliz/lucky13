#ifndef UTILITY_H
#define UTILITY_H

char *delete_char(char *str, char c);
void sigint_handler(int signal); //function to handle the SIGINT signal, to restore the default network settings when the user presses CTRL+C

#endif