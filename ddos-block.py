import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading
import time
import subprocess
from collections import defaultdict
import socket

INTERVALO_SEGUNDOS = 5
LIMITE_PPS = 20 

trafego_por_ip = defaultdict(list)
status_ip = {}
monitorando = False
ip_local = None

def get_ip_local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip_local = s.getsockname()[0]
    except Exception:
        ip_local = '127.0.0.1'
    finally:
        s.close()
    return ip_local

ip_local = get_ip_local()


root = tk.Tk()
root.title("🛡️ Bloqueador de Ataques DDoS")
root.geometry("740x550")
root.configure(bg="#1e1e1e")


titulo = tk.Label(root, text=f"Defesa de Rede Local - IP: {ip_local}", font=("Segoe UI", 18, "bold"), bg="#1e1e1e", fg="#fff")
titulo.pack(pady=10)

frame_porta = tk.Frame(root, bg="#1e1e1e")
frame_porta.pack(pady=5)

tk.Label(frame_porta, text="Porta para monitorar (TCP/UDP):", bg="#1e1e1e", fg="white", font=("Segoe UI", 12)).pack(side=tk.LEFT)
entrada_porta = tk.Entry(frame_porta, width=8, font=("Consolas", 12))
entrada_porta.pack(side=tk.LEFT, padx=5)
entrada_porta.insert(0, "") 

frame_botoes = tk.Frame(root, bg="#1e1e1e")
frame_botoes.pack(pady=5)

btn_iniciar = tk.Button(frame_botoes, text="▶ Iniciar Monitoramento", bg="#2e2e2e", fg="white", width=22)
btn_iniciar.grid(row=0, column=0, padx=5)
btn_parar = tk.Button(frame_botoes, text="⏹ Parar", bg="#2e2e2e", fg="white", width=22)
btn_parar.grid(row=0, column=1, padx=5)
btn_bloquear = tk.Button(frame_botoes, text="🚫 Bloquear IP Selecionado", bg="#5c1e1e", fg="white", width=22)
btn_bloquear.grid(row=0, column=2, padx=5)

frame_lista = tk.Frame(root, bg="#1e1e1e")
frame_lista.pack(padx=10, pady=10, fill=tk.X)

scrollbar_ips = tk.Scrollbar(frame_lista)
scrollbar_ips.pack(side=tk.RIGHT, fill=tk.Y)

lista_ips = tk.Listbox(frame_lista, bg="#121212", fg="lime", font=("Consolas", 12), height=8, yscrollcommand=scrollbar_ips.set, selectmode=tk.SINGLE)
lista_ips.pack(fill=tk.X)
scrollbar_ips.config(command=lista_ips.yview)

console = scrolledtext.ScrolledText(root, bg="#121212", fg="lightgreen", font=("Consolas", 10), state='disabled', height=15)
console.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)


def log(msg):
    console.configure(state='normal')
    console.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {msg}\n")
    console.configure(state='disabled')
    console.see(tk.END)

def atualizar_lista_ips():
    lista_ips.delete(0, tk.END)
    for ip in trafego_por_ip.keys():
        status = status_ip.get(ip, "normal")
        lista_ips.insert(tk.END, ip)
        if status == "suspeito":
            lista_ips.itemconfig(tk.END, fg="red")
        else:
            lista_ips.itemconfig(tk.END, fg="lime")

def analisar_pacote(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    ip_destino = pkt[IP].dst
    if ip_destino != ip_local:
        return

    porta_monitorada = entrada_porta.get().strip()
    if porta_monitorada:
        try:
            porta_valida = int(porta_monitorada)
            if pkt[TCP].dport != porta_valida:
                return
        except:
            pass 

    ip_origem = pkt[IP].src
    agora = time.time()

    if pkt.haslayer('Raw'):
        carga = pkt['Raw'].load
        metodos_http = [b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'OPTIONS', b'TRACE', b'CONNECT']
        if any(carga.startswith(m) for m in metodos_http):
            trafego_por_ip[ip_origem].append(agora)
        else:
            return
    else:
        return

    trafego_por_ip[ip_origem] = [t for t in trafego_por_ip[ip_origem] if agora - t <= INTERVALO_SEGUNDOS]

    pps = len(trafego_por_ip[ip_origem]) / INTERVALO_SEGUNDOS

    if pps >= LIMITE_PPS:
        if status_ip.get(ip_origem) != "suspeito":
            status_ip[ip_origem] = "suspeito"
            log(f"🚨 Ataque HTTP Flood detectado de {ip_origem} ({pps:.1f} requisições/s)")
    else:
        if status_ip.get(ip_origem) == "suspeito":
            status_ip[ip_origem] = "normal"
            log(f"ℹ️ Tráfego HTTP normalizado: {ip_origem}")

    atualizar_lista_ips()
    log(f"{ip_origem} → {pps:.1f} req/s HTTP na porta {pkt[TCP].dport}")

def iniciar_monitoramento():
    global monitorando
    if monitorando:
        return
    monitorando = True
    log("✅ Monitoramento iniciado")
    threading.Thread(target=lambda: sniff(prn=analisar_pacote, store=False), daemon=True).start()

def parar_monitoramento():
    global monitorando
    monitorando = False
    log("⏹ Monitoramento parado (sniffer continuará rodando em background)")

def bloquear_ip():
    selecao = lista_ips.curselection()
    if not selecao:
        messagebox.showwarning("Aviso", "Selecione um IP para bloquear.")
        return
    ip = lista_ips.get(selecao[0])
    try:
        cmd = f'netsh advfirewall firewall add rule name="Bloquear {ip}" dir=in action=block remoteip={ip}'
        subprocess.run(cmd, shell=True)
        log(f"🚫 IP bloqueado: {ip}")
    except Exception as e:
        log(f"Erro ao bloquear IP {ip}: {e}")

btn_iniciar.config(command=iniciar_monitoramento)
btn_parar.config(command=parar_monitoramento)
btn_bloquear.config(command=bloquear_ip)

root.mainloop()
