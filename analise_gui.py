import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, get_if_list
import pandas as pd
from collections import defaultdict, deque
import threading
import time

# --- Variáveis globais ---
capturando = False
lista_pacotes = []
ultimos_pacotes = deque(maxlen=50)  # últimos 50 pacotes

# --- Funções de captura e análise ---
def processa_pkt(pkt):
    if IP in pkt and TCP in pkt:
        ts = pkt.time
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        pacote_str = f"{ts:.6f} {src_ip} > {dst_ip}:{dst_port}"
        lista_pacotes.append((ts, src_ip, dst_port))
        ultimos_pacotes.append(pacote_str)
        atualizar_tabela_temp()
        atualizar_console()

def capturar_pacotes(interface, duracao):
    global capturando
    capturando = True
    sniff(iface=interface, prn=processa_pkt, timeout=duracao)
    capturando = False

def analisar_pacotes(lista):
    eventos_por_ip = defaultdict(list)
    for ts, src_ip, dst_port in lista:
        eventos_por_ip[src_ip].append((ts, dst_port))

    relatorio = []
    for ip, eventos in eventos_por_ip.items():
        total_eventos = len(eventos)
        detectado = "Não"

        eventos.sort()
        portas_window = set()
        inicio = 0
        for ts, port in eventos:
            portas_window.add(port)
            while ts - eventos[inicio][0] > 60:
                portas_window.discard(eventos[inicio][1])
                inicio += 1
            if len(portas_window) > 10:
                detectado = "Sim"
                break

        relatorio.append([ip, total_eventos, detectado])

    df = pd.DataFrame(relatorio, columns=["IP", "Total_Eventos", "Detectado_PortScan"])
    df.to_csv("relatorio.csv", index=False)
    return df

# --- Funções da GUI ---
def atualizar_tabela_temp():
    tabela.delete(*tabela.get_children())
    eventos_por_ip = defaultdict(list)
    for ts, src_ip, dst_port in lista_pacotes:
        eventos_por_ip[src_ip].append(dst_port)
    for ip, portas in eventos_por_ip.items():
        total_eventos = len(portas)
        detectado = "Sim" if len(set(portas)) > 10 else "Não"
        tabela.insert("", "end", values=[ip, total_eventos, detectado])

def atualizar_console():
    console_text.config(state="normal")
    console_text.delete("1.0", tk.END)
    for pkt in ultimos_pacotes:
        console_text.insert(tk.END, pkt + "\n")
    console_text.see(tk.END)
    console_text.config(state="disabled")

def iniciar_captura():
    interface = interface_var.get()
    try:
        duracao = int(duracao_entry.get())
    except ValueError:
        messagebox.showerror("Erro", "Informe um valor válido para duração")
        return
    if not interface:
        messagebox.showerror("Erro", "Selecione uma interface")
        return

    lista_pacotes.clear()
    ultimos_pacotes.clear()
    status_label.config(text="Capturando tráfego...")
    progresso_bar["value"] = 0
    progresso_bar["maximum"] = duracao

    def thread_captura():
        start_time = time.time()
        capturar_pacotes(interface, duracao)
        progresso_bar["value"] = duracao
        status_label.config(text="Captura finalizada. Gerando relatório...")
        analisar_pacotes(lista_pacotes)
        status_label.config(text="Análise concluída! Relatório gerado: relatorio.csv")

    def thread_barra():
        start_time = time.time()
        while capturando:
            tempo_passado = time.time() - start_time
            progresso_bar["value"] = min(tempo_passado, duracao)
            time.sleep(0.5)

    t1 = threading.Thread(target=thread_captura)
    t2 = threading.Thread(target=thread_barra)
    t1.start()
    t2.start()

# --- GUI ---
root = tk.Tk()
root.title("Analisador de Tráfego Dark Mode")
root.configure(bg="black")

# Estilos dark mode
style = ttk.Style()
style.theme_use('clam')
style.configure("TFrame", background="black")
style.configure("TLabel", background="black", foreground="lime")
style.configure("TButton", background="black", foreground="lime")
style.configure("TCombobox", fieldbackground="black", background="black", foreground="lime")
style.configure("Treeview", background="black", foreground="lime", fieldbackground="black")
style.configure("Treeview.Heading", background="black", foreground="lime")

frame = ttk.Frame(root, padding=10)
frame.grid(row=0, column=0, sticky="NSEW")

# Dropdown de interfaces
ttk.Label(frame, text="Interface:").grid(row=0, column=0, sticky="W")
interface_var = tk.StringVar()
interfaces_disponiveis = get_if_list()
interface_menu = ttk.Combobox(frame, textvariable=interface_var, values=interfaces_disponiveis, state="readonly")
interface_menu.grid(row=0, column=1, sticky="EW")
if interfaces_disponiveis:
    interface_var.set(interfaces_disponiveis[0])

# Entrada duração
ttk.Label(frame, text="Duração (s):").grid(row=1, column=0, sticky="W")
duracao_entry = tk.Entry(frame, bg="black", fg="lime", insertbackground="lime", font=("Consolas", 10))
duracao_entry.grid(row=1, column=1, sticky="EW")
duracao_entry.insert(0, "60")

# Botão iniciar
iniciar_btn = ttk.Button(frame, text="Iniciar Captura", command=iniciar_captura)
iniciar_btn.grid(row=2, column=0, columnspan=2, pady=5)

# Barra de progresso
progresso_bar = ttk.Progressbar(frame, orient="horizontal", length=300, mode="determinate")
progresso_bar.grid(row=3, column=0, columnspan=2, pady=5)

# Label status
status_label = ttk.Label(frame, text="Aguardando captura...", foreground="lime")
status_label.grid(row=4, column=0, columnspan=2, sticky="W")

# Tabela resultados
tabela = ttk.Treeview(frame, columns=("IP", "Total_Eventos", "Detectado_PortScan"), show="headings", height=8)
tabela.heading("IP", text="IP")
tabela.heading("Total_Eventos", text="Total_Eventos")
tabela.heading("Detectado_PortScan", text="Detectado_PortScan")
tabela.grid(row=5, column=0, columnspan=2, pady=5, sticky="NSEW")
style.configure("Treeview", font=("Consolas", 10), background="black", foreground="lime", fieldbackground="black")
style.configure("Treeview.Heading", font=("Consolas", 10, "bold"), background="black", foreground="lime")


# Console de pacotes (últimos 50 pacotes)
console_label = ttk.Label(frame, text="Últimos Pacotes Capturados:")
console_label.grid(row=6, column=0, columnspan=2, sticky="W")
console_text = tk.Text(frame, height=15, width=80, bg="black", fg="lime", insertbackground="lime", font=("Consolas", 10))
console_text.grid(row=7, column=0, columnspan=2, pady=5)
console_text.configure(state="disabled")

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
frame.columnconfigure(1, weight=1)

root.mainloop()

