import numpy as np
import matplotlib.pyplot as plt
import os

def run_statistical_analysis(memory_view, num_rows, num_cols):
    print(f"[Python] Ricevuta memory_view. Dimensioni: {num_rows}x{num_cols}")
    
    #collega la memoria C a NumPy
    flat_array = np.frombuffer(memory_view, dtype=np.int64)
    time_matrix = flat_array.reshape((num_rows, num_cols))

    #ordina la matrice e cancella i due valori più alti e i 2 valori più bassi (tolgo gli outlier)
    sorted_matrix = np.sort(time_matrix, axis=1)
    trim_count = int(num_cols * 0.35)
    if num_cols > 2:
        clean_time_matrix = sorted_matrix[:, trim_count : -trim_count]
    else:
        clean_time_matrix = sorted_matrix

    #se non funziona provare l'implementazione con differenza rispetto alla mediana / percentile
    
    #calcola la mediana dei tempi per ogni byte
    #median_times = np.mean(clean_time_matrix, axis=1)
    median_times = np.median(clean_time_matrix, axis=1)

    #trova l'indice (il byte) con il tempo mediano più basso 
    best_guess = np.argmin(median_times)

    # L'indice esatto che ti aspetti (0x3e * 256 + 0xb4) [0x35B4]
    expected_index = 0x3839

    print(f"[Python] Tempo mediano del Falso Minimo (riga {best_guess}): {median_times[best_guess]}")
    print(f"[Python] Tempo mediano della riga CORRETTA (riga {expected_index}): {median_times[expected_index]}")
    print(f"[Python] Tempo mediano medio di tutte le righe: {np.mean(median_times)}")
    
    print(f"[Python] Analisi conclusa. Trovata anomalia all'indice: {hex(best_guess)}")



    #PARTE DI GRAFICI E DEBUGGING DEI TEMPI

    # --- 1. STAMPA DEI SEMPLICI VALORI (TOP 10) ---
    print("\n[Python] --- TOP 10 CANDIDATI (Tempi più bassi) ---")
    # argsort restituisce gli indici ordinati dal valore più basso al più alto
    top_10_indices = np.argsort(median_times)[:10]
    for i, idx in enumerate(top_10_indices):
        diff_from_mean = median_times[idx] - np.mean(median_times)
        print(f"  {i+1}. Indice: {hex(idx):<6} -> Tempo: {median_times[idx]} ns (Diff da media: {diff_from_mean:.2f} ns)")
    print("--------------------------------------------------\n")

    # --- 2. GENERAZIONE DEL GRAFICO ---
    plt.figure(figsize=(14, 7))
    
    if num_rows <= 256:
        # Per 1 byte (256 valori), il grafico a barre è perfetto
        plt.bar(range(num_rows), median_times, color='skyblue', edgecolor='black')
        plt.axhline(y=np.mean(median_times), color='orange', linestyle='--', label='Media Globale')
    else:
        # Per 2 byte (65536 valori), usiamo plot e scatter per non far esplodere la RAM grafica
        plt.plot(range(num_rows), median_times, color='lightgray', alpha=0.5, label='Tempi mediani')
        plt.axhline(y=np.mean(median_times), color='orange', linestyle='--', alpha=0.8, label='Media Globale')
        
        # Evidenziamo visivamente i due punti critici
        plt.scatter(best_guess, median_times[best_guess], color='red', s=80, label='Minimo Trovato', zorder=5)
        if expected_index < num_rows:
            plt.scatter(expected_index, median_times[expected_index], color='green', s=80, label='Valore Atteso', zorder=5)

    plt.title(f'Distribuzione dei Tempi Mediani (Dimensione: {num_rows})', fontsize=14)
    plt.xlabel('Ipotesi (Indice / Byte)', fontsize=12)
    plt.ylabel('Tempo Mediano (nanosecondi)', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.7)
    plt.legend()
    
    # Salviamo l'immagine invece di chiamare plt.show()
    plot_filename = "timing_analysis_plot.png"
    plt.savefig(plot_filename, dpi=150, bbox_inches='tight')
    print(f"[Python] Grafico salvato con successo in: {os.path.abspath(plot_filename)}")
    
    # Chiude la figura per liberare memoria (importante se si fa in loop!)
    plt.close()


    return int(best_guess)

