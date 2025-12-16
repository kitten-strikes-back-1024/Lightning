from scapy.all import IP, TCP, sr1, send

def osdetect(target, openport):
    pkt = IP(dst=target)/TCP(dport=openport, flags="S")
    received = sr1(pkt, timeout=3, retry=1, verbose=0)

    if not received or not received.haslayer(TCP):
        print("No response / filtered")
        return

    # Only proceed if SYN-ACK
    if received[TCP].flags != 0x12:
        print("Port not open or unexpected response")
        return

    ttl = received[IP].ttl
    window = received[TCP].window
    opts = [opt[0] for opt in received[TCP].options]
    options = received[TCP].options

    print(f"TTL={ttl}, Window={window}, Options={options}")
    print("OS DETECTOR ENABLED...\n")

    accuracy = 0

    # TTL heuristic
    if ttl <= 64:
        accuracy += 40
    elif ttl <= 128:
        accuracy -= 40

    # Window size heuristic
    if window in (5840, 29200, 64240):
        accuracy += 40
    elif window in (8192, 65535):
        accuracy -= 40

    # TCP option order heuristic
    if opts == ['MSS', 'SACK', 'TS', 'NOP', 'WS']:
        accuracy += 20
    elif opts == ['MSS', 'NOP', 'WS', 'NOP', 'NOP', 'SACK']:
        accuracy -= 20

    # Final decision
    if accuracy >= 40:
        print(f"OS is LINUX/UNIX-like | Confidence: {accuracy}%")
    elif accuracy <= -40:
        print(f"OS is Windows | Confidence: {abs(accuracy)}%")
    else:
        print(f"OS unclear / filtered | Score: {accuracy}")

    # Be polite
    send(IP(dst=target)/TCP(dport=openport, flags="R"), verbose=0)
