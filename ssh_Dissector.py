
from scapy.all import sniff, wrpcap, Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP

def Full_Duplex_Sessions(p):
    
    sess = "Other"
    if 'Ether' in p:
        if 'IP' in p:
            if 'TCP' in p:
                sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport],key=str))
            elif 'UDP' in p:
                sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport] ,key=str))
            elif 'ICMP' in p:
                sess = str(sorted(["ICMP", p[IP].src, p[IP].dst, p[ICMP].code, p[ICMP].type, p[ICMP].id] ,key=str)) 
            else:
                sess = str(sorted(["IP", p[IP].src, p[IP].dst, p[IP].proto] ,key=str)) 
        elif 'ARP' in p:
            sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst],key=str)) 
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")

    return sess




def TCPSessionFilter(sessions):


    Keys=list(sessions.keys())
    Values=list(sessions.values())

    TCPSessions = {}

    for (KeyEntry, ValueEntry) in zip(Keys,Values):        
        Key = KeyEntry.replace("[","").replace("]","").replace("'","").replace(", ","-").split("-")
        
        if len(Key) == 5: 
            if Key[4] == "TCP": 
                TCPSessions [KeyEntry] = ValueEntry
    
    return TCPSessions



def SSHSessionFilter(sessions):

    Keys=list(sessions.keys())
    Values=list(sessions.values())

    SSHSessions = {}
    SaveSSHSession = False

    for Kindex,Vindex in zip(Keys, Values): 
        for Yindex in Vindex:
            if Yindex[TCP].dport == 22 or Yindex[TCP].sport == 22: 
                SaveSSHSession = True
        
        if (SaveSSHSession): 
            SSHSessions [Kindex] = Vindex
            SaveSSHSession = False 
    

    return SSHSessions


# SSH brute-force attempts typically result in many short sessions due to failed login attempts.
# in contrast, a successful SSH login usually produces longer sessions .
# this function estimates that based on a size threshold (default 7500 bytes).
def SSHBruteAnalysis(SSHSessions, threshold=7500):
    Keys = list(SSHSessions.keys())
    Values = list(SSHSessions.values())

    SSHsuccess = 0
    SSHfail = 0
    SSHFailSessions = {}
    SSHattacks = {} 

    for Kindex, Vindex in zip(Keys, Values):
        SessionLength = 0
        for Yindex in Vindex:
            SessionLength += (Yindex[IP].len + 14)

        if SessionLength < threshold:
            SSHFailSessions[Kindex] = Vindex
            SSHfail += 1
        else:
            SSHsuccess += 1

        
        first_pkt = Vindex[0]
        if IP in first_pkt:
            AttackKey = f"{first_pkt[IP].src}->{first_pkt[IP].dst}"
            SSHattacks[AttackKey] = SSHattacks.get(AttackKey, 0) + 1

    
    print("\nSSH Success Count:", SSHsuccess)
    print("SSH Failure Count:", SSHfail)

    
    for key, value in SSHattacks.items():
         print(f"\n{key} : {value}")

def activate_ssh_analysis(pcap_file):
    
    Capture=sniff(offline=pcap_file)
    
    SSHThreshold = 7500

    FullDuplexSessions = Capture.sessions(Full_Duplex_Sessions) 

    TCPsessions = TCPSessionFilter (FullDuplexSessions)

    SSHSessions = SSHSessionFilter (TCPsessions)

    if len(SSHSessions) != 0: 
        SSHBruteAnalysis (SSHSessions, SSHThreshold)

    
