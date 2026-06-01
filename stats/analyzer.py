import numpy as np
import matplotlib.pyplot as plt

def run_statistical_analysis(memory_view, num_rows, num_cols):
    print(f"       [Python] Ricevuta memory_view. Dimensioni: {num_rows}x{num_cols}")
    
    # Collega la memoria C a NumPy
    flat_array = np.frombuffer(memory_view, dtype=np.int64)
    time_matrix = flat_array.reshape((num_rows, num_cols))
    
    # Calcola la mediana dei tempi per ogni byte
    median_times = np.median(time_matrix, axis=1)

    # visualizza i tempi mediani
    #plt.bar(range(len(median_times)), median_times)
    #plt.show()
    #plt.figure(figsize=(10, 5))
    #plt.plot(median_times, marker='o')
    #plt.title('Median Times per Byte Index')
    #plt.xlabel('Byte Index')
    #plt.ylabel('Median Time (cycles)')
    #plt.grid()
    #plt.show()  
    
    # Trova l'indice (il byte) con il tempo mediano più alto
    best_guess = np.argmax(median_times)
    
    print(f"       [Python] Analisi conclusa. Trovata anomalia all'indice: {hex(best_guess)}")

    return int(best_guess)

