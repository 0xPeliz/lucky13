"""import numpy as np
import matplotlib.pyplot as plt
import os

def run_statistical_analysis(memory_view, num_rows, num_cols):
    print(f"[Python] Ricevuta memory_view. Dimensioni: {num_rows}x{num_cols}")
    
    #collega la memoria C a NumPy
    flat_array = np.frombuffer(memory_view, dtype=np.int64)
    time_matrix = flat_array.reshape((num_rows, num_cols))

    #ordina la matrice e cancella il 35% dei valori più alti e più bassi 
    sorted_matrix = np.sort(time_matrix, axis=1)
    trim_count = int(num_cols * 0.20)
    if num_cols > 2:
        clean_time_matrix = sorted_matrix[:, trim_count : -trim_count]
    else:
        clean_time_matrix = sorted_matrix
    
    #calcola la mediana dei tempi per ogni byte (axis = 1 indica che vogliamo la mediana calcolata lungo le righe, quindi per ogni ipotesi di byte)
    median_times = np.mean(clean_time_matrix, axis=1)

    # Trova l'indice (il byte) con il tempo MINIMO
    best_guess = np.argmin(median_times)

    # FIX: Adattiamo l'indice atteso in base a quale fase stiamo testando
    if num_rows == 256:
        # Se è il test veloce (Fase 2), ci aspettiamo il byte 0x38 (56 in decimale)
        expected_index = 0x38
    else:
        # Se è l'attacco completo (Fase 1), ci aspettiamo 0x3839
        expected_index = 0x3839

    print(f"[Python] Tempo medio del Minimo Trovato (riga {hex(best_guess)}): {median_times[best_guess]:.2f}")
    
    if expected_index < num_rows:
        print(f"[Python] Tempo medio della riga CORRETTA (riga {hex(expected_index)}): {median_times[expected_index]:.2f}")
    
    print(f"[Python] Tempo medio globale di tutte le righe: {np.mean(median_times):.2f}")
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


    return int(best_guess) """

import numpy as np
import matplotlib.pyplot as plt
import os

def run_statistical_analysis(memory_view, num_rows, num_cols):
    print(f"[Python] Ricevuta memory_view. Dimensioni: {num_rows}x{num_cols}")
    
    # Collega la memoria C a NumPy
    flat_array = np.frombuffer(memory_view, dtype=np.int64)
    time_matrix = flat_array.reshape((num_rows, num_cols))

    # 1. ORDINA LA MATRICE: dal tempo più veloce al più lento per ogni singolo byte
    sorted_matrix = np.sort(time_matrix, axis=1)
    
    # 2. ISOLA I GIRI PERFETTI (Filtro per il limite fisico dell'hardware)
    # Ignoriamo le percentuali. Prendiamo ESATTAMENTE i 25 pacchetti 
    # più veloci in assoluto su 50.000. Questi sono i pacchetti che hanno 
    # attraversato il Kernel senza alcuna interruzione.
    keep_count = 25
    
    if num_cols > keep_count:
        clean_time_matrix = sorted_matrix[:, :keep_count]
    else:
        clean_time_matrix = sorted_matrix

    # 3. CALCOLO DELLA MEDIA DEL PICCO HARDWARE
    # Usiamo np.mean sui 25 campioni dorati per livellare fluttuazioni 
    # di 1-2 nanosecondi, estraendo il segnale puro del silicio.
    mean_times = np.mean(clean_time_matrix, axis=1)

    # 4. TROVA IL VINCITORE (argmin)
    # Secondo la teoria di AlFardan-Paterson, il padding valido impiega un 
    # blocco SHA-1 in meno. Meno calcoli = tempo MINORE.
    best_guess = np.argmin(mean_times)

    # Impostiamo il byte che ci aspettiamo per i print di controllo
    if num_rows <= 256:
        expected_index = 0x38 # Fase 2: Ci aspettiamo il penultimo byte
    else:
        expected_index = 0x3839 # Fase 1: Ci aspettiamo gli ultimi 2 byte

    print(f"[Python] Tempo medio del MINIMO Trovato (riga {hex(best_guess)}): {mean_times[best_guess]:.2f} ns")
    
    if expected_index < num_rows:
        print(f"[Python] Tempo medio della riga CORRETTA (riga {hex(expected_index)}): {mean_times[expected_index]:.2f} ns")
    
    print(f"[Python] Tempo globale del 10% più veloce (Media): {np.mean(mean_times):.2f} ns")
    print(f"[Python] Analisi conclusa. Trovata anomalia all'indice: {hex(best_guess)}")


    # --- PARTE DI GRAFICI E DEBUGGING DEI TEMPI ---

    print("\n[Python] --- TOP 10 CANDIDATI (Tempi più bassi) ---")
    top_10_indices = np.argsort(mean_times)[:10]
    for i, idx in enumerate(top_10_indices):
        diff_from_mean = np.mean(mean_times) - mean_times[idx]
        print(f"  {i+1}. Indice: {hex(idx):<6} -> Tempo: {mean_times[idx]:.2f} ns (Più veloce della media di: {diff_from_mean:.2f} ns)")
    print("--------------------------------------------------\n")

    # --- GENERAZIONE DEL GRAFICO ---
    plt.figure(figsize=(14, 7))
    
    if num_rows <= 256:
        plt.bar(range(num_rows), mean_times, color='skyblue', edgecolor='black')
        plt.axhline(y=np.mean(mean_times), color='orange', linestyle='--', label='Media Globale (Top 10%)')
    else:
        plt.plot(range(num_rows), mean_times, color='lightgray', alpha=0.5, label='Tempi')
        plt.axhline(y=np.mean(mean_times), color='orange', linestyle='--', alpha=0.8, label='Media Globale (Top 10%)')
        
        plt.scatter(best_guess, mean_times[best_guess], color='red', s=80, label='Minimo Trovato', zorder=5)
        if expected_index < num_rows:
            plt.scatter(expected_index, mean_times[expected_index], color='green', s=80, label='Valore Atteso', zorder=5)

    # Fissiamo il limite Y per rendere visibili anche differenze di 50 nanosecondi
    plt.ylim(np.min(mean_times) - 200, np.max(mean_times) + 200)

    plt.title(f'Distribuzione dei Tempi (Filtrati al 10% più veloce) - Dim: {num_rows}', fontsize=14)
    plt.xlabel('Ipotesi (Indice / Byte)', fontsize=12)
    plt.ylabel('Tempo Medio (nanosecondi)', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.7)
    plt.legend()
    
    plot_filename = "timing_analysis_plot.png"
    plt.savefig(plot_filename, dpi=150, bbox_inches='tight')
    print(f"[Python] Grafico salvato con successo in: {os.path.abspath(plot_filename)}")
    plt.close()

    return int(best_guess)

