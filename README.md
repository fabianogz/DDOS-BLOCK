# DDOS-BLOCK

Este programa em Python com interface Tkinter monitora o tráfego de rede local, detecta ataques do tipo DDoS (especialmente HTTP Flood) e permite bloquear IPs suspeitos via firewall do Windows.

---

## ⚠️ Aviso importante

**Este software é destinado exclusivamente para fins educacionais e testes autorizados em redes próprias.**

O uso deste programa em redes alheias sem autorização é ilegal e pode acarretar em sérias consequências legais.

O autor não se responsabiliza por usos indevidos ou ilegais deste código.

---

## Funcionalidades

- Monitoramento em tempo real do tráfego de pacotes TCP/UDP para o IP local
- Detecção de ataques HTTP Flood baseado em requisições por segundo
- Interface moderna com console e lista de IPs, destacando IPs suspeitos em vermelho
- Bloqueio manual de IPs suspeitos via firewall do Windows
- Filtro por porta para monitorar serviços específicos (ex: porta 80 ou 8000)

---

## Requisitos

- Python 3.x
- Bibliotecas: scapy, tkinter (normalmente já inclusa)
- Npcap instalado no Windows para captura de pacotes (https://nmap.org/npcap/)

---

## Como usar

1. Clone ou baixe o repositório.
2. Instale as dependências:
    ```bash
    pip install scapy
    ```
3. Execute o programa:
    ```bash
    python bloqueador.py
    ```
4. Digite a porta que deseja monitorar e clique em "Iniciar Monitoramento".
5. Observe os IPs na lista e bloqueie os suspeitos com o botão "Bloquear IP Selecionado".

---

## Disclaimer

Este programa é uma ferramenta didática para aprendizado sobre segurança de redes e monitoramento de tráfego. Sempre respeite a legislação local e utilize em ambientes controlados e autorizados.



