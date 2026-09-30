
import numpy as np
import matplotlib.pyplot as plt
import os

def run_statistical_analysis(memory_view, num_rows, num_cols):
    print(f"[Python] ricevuta memory_view. dimensioni: {num_rows}x{num_cols}")
    
    # Collega la memoria C a NumPy
    flat_array = np.frombuffer(memory_view, dtype=np.int64)
    time_matrix = flat_array.reshape((num_rows, num_cols))

    sorted_matrix = np.sort(time_matrix, axis=1)
    
    keep_count = 25
    
    if num_cols > keep_count:
        clean_time_matrix = sorted_matrix[:, :keep_count]
    else:
        clean_time_matrix = sorted_matrix

    mean_times = np.mean(clean_time_matrix, axis=1)

    best_guess = np.argmin(mean_times)

    # Impostiamo il byte che ci aspettiamo per i print di controllo
    if num_rows <= 256:
        expected_index = 0x38 
    else:
        expected_index = 0x3839 

    print(f"[Python] tempo medio del minimo trovato (riga {hex(best_guess)}): {mean_times[best_guess]:.2f} ns")
    
    if expected_index < num_rows:
        print(f"[Python] tempo medio della riga corretta (riga {hex(expected_index)}): {mean_times[expected_index]:.2f} ns")
    
    print(f"[Python] tempo globale del 10% più veloce (Media): {np.mean(mean_times):.2f} ns")
    print(f"[Python] analisi conclusa. Trovata anomalia all'indice: {hex(best_guess)}")

    # grafici e debugging dei tempi
    print("\n[Python] candidati con il minor tempo di esecuzione")
    top_10_indices = np.argsort(mean_times)[:10]
    for i, idx in enumerate(top_10_indices):
        diff_from_mean = np.mean(mean_times) - mean_times[idx]
        print(f"  {i+1}. Indice: {hex(idx):<6} -> Tempo: {mean_times[idx]:.2f} ns (Più veloce della media di: {diff_from_mean:.2f} ns)")
    print("--------------------------------------------------\n")

    # generazione del grafico
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

    plt.ylim(np.min(mean_times) - 200, np.max(mean_times) + 200)

    plt.title(f'distribuzione dei tempi (filtrati al 10% più veloce) con dimensione: {num_rows}', fontsize=14)
    plt.xlabel('ipotesi (indice / byte)', fontsize=12)
    plt.ylabel('tempo medio (nanosecondi)', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.7)
    plt.legend()
    
    plot_filename = "timing_analysis_plot.png"
    plt.savefig(plot_filename, dpi=150, bbox_inches='tight')
    print(f"[Python] grafico salvato con successo in: {os.path.abspath(plot_filename)}")
    plt.close()

    return int(best_guess)

