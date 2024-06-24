import os
import netifaces
import socket
from scapy.all import ARP, Ether, srp, IP, TCP, sr1
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import nest_asyncio
import asyncio
import logging
from telegram import InputMediaPhoto

# Configura il logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Applica la patch per consentire l'incapsulamento del ciclo di eventi
nest_asyncio.apply()

# Configura il token del tuo bot Telegram
TELEGRAM_BOT_TOKEN = 'TUO_TOKEN'
CHAT_ID = 'TUO_ID'

# Evento per controllare lo stato di esecuzione delle scansioni
scanning_task = None
stop_scan_flag = False
application = None

def validate_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

# Funzione per ottenere la rete locale in cui si trova il dispositivo
def get_local_network():
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default')
    if default_gateway is None:
        raise Exception("❌ Impossibile trovare il gateway predefinito.")
    
    interface = default_gateway[netifaces.AF_INET][1]
    addresses = netifaces.ifaddresses(interface)
    ipv4 = addresses[netifaces.AF_INET][0]
    ip_address = ipv4['addr']
    netmask = ipv4['netmask']

    # Calcola l'indirizzo di rete
    ip_parts = ip_address.split('.')
    netmask_parts = netmask.split('.')
    network_parts = [str(int(ip_parts[i]) & int(netmask_parts[i])) for i in range(4)]
    network = '.'.join(network_parts) + '/' + str(sum(bin(int(x)).count('1') for x in netmask_parts))
    
    return network

def resolve_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
    except Exception as e:
        logger.error(f"❌ Errore durante la risoluzione dell'indirizzo MAC: {e}")
        return None

    for _, rcv in ans:
        if ARP in rcv and Ether in rcv:
            return rcv[Ether].src

    logger.warning(f"❌ Indirizzo MAC non trovato per l'IP: {ip}. Utilizzo della modalità broadcast.")
    return None

async def run():
    await add_trovaIP_handler()

async def add_trovaIP_handler():
    if application is not None:  # Verifica che application sia stata definita
        await application.add_handler(CommandHandler("trovaIP", find_port_on_ip))

async def scan_and_notify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) == 0:
        await scan_local_network(context)
    else:
        target_gateway_ip = context.args[0]
        if validate_ipv4(target_gateway_ip):
            await scan_network(target_gateway_ip, context)
        else:
            await context.bot.send_message(chat_id=CHAT_ID, text="❌ Indirizzo IP non valido. Assicurati di inserire un indirizzo IPv4 valido.")

async def scan_local_network(context: ContextTypes.DEFAULT_TYPE):
    devices = await scan_network(get_local_network(), context)
    if devices:
        message = "ℹ️ Scansione completata. Dispositivi trovati sulla rete:\n"
        for device in devices:
            message += f"IP: {device['ip']}, MAC {device['mac']}\n"
    else:
        message = "ℹ️ Scansione completata. Nessun dispositivo trovato sulla rete."

    await context.bot.send_message(chat_id=CHAT_ID, text=message)

# Funzione per eseguire la scansione della rete
async def scan_network(target_gateway_ip, context: ContextTypes.DEFAULT_TYPE):
    network = get_local_network()
    await context.bot.send_message(chat_id=CHAT_ID, text=f"ℹ️ Scansione della rete: {network}")

    arp = ARP(pdst=network)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    num_hosts = len(result)
    for i, (sent, received) in enumerate(result, 1):
        device = {'ip': received.psrc, 'mac': received.hwsrc}
        devices.append(device)

        # Calcolare la percentuale di completamento
        percent_complete = (i / num_hosts) * 100
        if i % 5 == 0:  # Invia aggiornamenti ogni 5 dispositivi trovati
            await context.bot.send_message(chat_id=CHAT_ID, text=f"🔄 Scansione in corso, {percent_complete:.2f}% completata")

        await context.bot.send_message(chat_id=CHAT_ID, text=f"✔️ Trovato dispositivo: IP {device['ip']}, MAC {device['mac']}")

    return devices

# Funzione per eseguire la scansione delle porte aperte
async def scan_ports(target_ip, context: ContextTypes.DEFAULT_TYPE):
    open_ports = []
    ports = range(1, 1025)
    num_ports = len(ports)

    await context.bot.send_message(chat_id=CHAT_ID, text=f"⏳ Inizio scansione delle porte su {target_ip}...")

    progress_message = await context.bot.send_message(chat_id=CHAT_ID, text="🔄 Scansione in corso, 0.00% completata")
    
    for idx, port in enumerate(ports, 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
                logger.debug(f"✔️ Porta {port} aperta su {target_ip} ({idx}/{num_ports})")
            else:
                logger.debug(f"❌ Porta {port} chiusa su {target_ip} ({idx}/{num_ports})")
            s.close()
        except Exception as e:
            logger.error(f"❌ Errore durante il controllo della porta {port}: {e}")

        # Calcola la percentuale di completamento
        percent_complete = (idx / num_ports) * 100
        
        # Aggiorna il messaggio di progresso con la nuova percentuale
        await context.bot.edit_message_text(chat_id=CHAT_ID, message_id=progress_message.message_id, text=f"🔄 Scansione in corso, {percent_complete:.2f}% completata")
        
        # Attendi prima di continuare con la prossima scansione
        await asyncio.sleep(0.1)

    await context.bot.send_message(chat_id=CHAT_ID, text="✔️ Scansione completata!")
    logger.debug("✔️ Scansione completata.")
    return open_ports

# Funzione per eseguire la scansione e inviare i risultati tramite Telegram
async def scan_ports_and_notify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) == 0:
        await update.message.reply_text("ℹ️ Fornisci un indirizzo IP di destinazione. Esempio: /porte 192.168.1.1")
        logger.debug("❌ Nessun indirizzo IP fornito.")
        return

    target_ip = context.args[0]
    if validate_ipv4(target_ip):
        logger.debug(f"Ricevuto comando per scansionare porte su IP: {target_ip}")
        await scan_ports(target_ip, context)
    else:
        await context.bot.send_message(chat_id=CHAT_ID, text="❌ Indirizzo IP non valido. Assicurati di inserire un indirizzo IPv4 valido.")

async def find_port_on_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    command = context.args

    # Verifica che il comando contenga esattamente due argomenti
    if len(command) != 2:
        await update.message.reply_text("ℹ️ Utilizzo corretto: /trovaIP <indirizzo IP> <numero porta>")
        return

    target_ip = command[0]
    target_port = command[1]

    # Verifica la validità dell'indirizzo IP
    if not validate_ipv4(target_ip):
        await update.message.reply_text("❌ Indirizzo IP non valido. Assicurati di inserire un indirizzo IPv4 valido.")
        return

    try:
        target_port = int(target_port)
    except ValueError:
        await update.message.reply_text("❌ Numero di porta non valido. Inserisci un numero di porta valido.")
        return

    if not 1 <= target_port <= 65535:
        await update.message.reply_text("❌ Numero di porta non valido. Inserisci un numero di porta compreso tra 1 e 65535.")
        return

    # Esegui la scansione della porta sull'IP specificato
    res = await check_port(target_ip, target_port, context)
    
    if res:
        await update.message.reply_text(f"✔️ La porta {target_port} su {target_ip} è aperta.")
    else:
        await update.message.reply_text(f"❌ La porta {target_port} su {target_ip} è chiusa.")

async def check_port(ip, port, context: ContextTypes.DEFAULT_TYPE):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception as e:
        logger.error(f"❌ Errore durante il controllo della porta {port} su {ip}: {e}")
        return False

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_message = "👋 Benvenuto! Sono il tuo Bot di scansione di reti e porte.\n\n🤖 Ecco cosa posso fare:\n\n" \
                      "🚀 /scan - Per scansionare la rete locale in cerca di dispositivi\n" \
                      "👩‍🚀 /trovaIP <indirizzo IP> <numero porta> - Per trovare le porte aperte su un determinato IP\n" \
                      "🔭 /porte <indirizzo IP> - Per scansionare le porte aperte su un IP specifico\n\n" \
                      "🕵️ Creato da: Van Zwam Arjen - www.MondoHacking.com"
    
    # Example image URL, replace it with your image URL
    image_url = "C:\\Users\\OMEN\\Desktop\\ScannerAVS\\Scanner.jpg"
    
    # Send the welcome message along with the image
    await context.bot.send_photo(chat_id=update.effective_chat.id, photo=image_url, caption=welcome_message)

async def main():
    global application  # Specifichiamo che application è globale
    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("scan", scan_and_notify))
    application.add_handler(CommandHandler("porte", scan_ports_and_notify))
    application.add_handler(CommandHandler("trovaIP", find_port_on_ip))

    logger.debug("Applicazione avviata, inizio polling...")
    await application.run_polling()

if __name__ == '__main__':
    try:
        asyncio.run(main())
        asyncio.get_event_loop().run_forever()
    except Exception as e:
        print(f"❌ Errore durante l'esecuzione dello script: {str(e)}")
