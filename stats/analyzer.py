import numpy as np

def run_statistical_analysis(memory_view, num_rows, num_cols):
    print(f"       [Python] Ricevuta memory_view. Dimensioni: {num_rows}x{num_cols}")
    
    # Collega la memoria C a NumPy (Zero-Copy)
    flat_array = np.frombuffer(memory_view, dtype=np.int64)
    time_matrix = flat_array.reshape((num_rows, num_cols))
    
    # Calcola la mediana dei tempi per ogni byte
    median_times = np.median(time_matrix, axis=1)
    
    # Trova l'indice (il byte) con il tempo mediano più alto
    best_guess = np.argmax(median_times)
    
    print(f"       [Python] Analisi conclusa. Trovata anomalia all'indice: {hex(best_guess)}")

    return int(best_guess)

