import numpy as np
import matplotlib.pyplot as plt

def run_statistical_analysis(memory_view, num_rows, num_cols):
    print(f"[Python] Ricevuta memory_view. Dimensioni: {num_rows}x{num_cols}")
    
    #collega la memoria C a NumPy
    flat_array = np.frombuffer(memory_view, dtype=np.int64)
    time_matrix = flat_array.reshape((num_rows, num_cols))

    #ordina la matrice e cancella i due valori più alti e i 2 valori più bassi (tolgo gli outlier)
    sorted_matrix = np.sort(time_matrix, axis=1)
    clean_time_matrix = sorted_matrix[:, 2: -2]

    #se non funziona provare l'implementazione con differenza rispetto alla mediana / percentile
    
    #calcola la mediana dei tempi per ogni byte
    median_times = np.median(clean_time_matrix, axis=1)

    #trova l'indice (il byte) con il tempo mediano più basso 
    best_guess = np.argmin(median_times)
    
    print(f"[Python] Analisi conclusa. Trovata anomalia all'indice: {hex(best_guess)}")

    return int(best_guess)

