#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../attacker/include/utility.h"
#include "stats.h"

int main(){

    printf("[TEST] Test inizializzazione ambiente Python \n");
    init_python_environment();

    //alloca ad inizializza la struct dell'attacco con dati fittizi
    struct attack_result attack_res;
    for(int i=0; i<256; i++){
        for(int j=0; j<L_SIZE; j++){
            attack_res.time_meas[i][j] = (i * L_SIZE) + j;
        }
    }

    // Simuliamo che il byte 0x42 (66) sia quello corretto, dandogli un tempo anomalo
    int byte_segreto = 0x42;
    for(int j = 0; j < L_SIZE; j++) {
        attack_res.time_meas[byte_segreto][j] = 5000 + j; // Spike di latenza
    }

    printf("[TEST] Dati generati. Lancio l'analisi statistica (cercando un'anomalia a 0x42)...\n");
    
    // Chiama la funzione C che invoca Python
    int risultato = analyze_single_byte(&attack_res);

    printf("[TEST] L'analizzatore Python ha restituito il byte: 0x%02x\n", risultato);
    
    if (risultato == byte_segreto) {
        printf("\x1b[32m[SUCCESSO] L'integrazione C-Python funziona perfettamente!\x1b[0m\n");
    } else {
        printf("\x1b[31m[ERRORE] Il risultato non coincide con l'anomalia inserita.\x1b[0m\n");
    }

    printf("[TEST] Chiusura ambiente Python...\n");
    close_python_environment();

    return 0;
}