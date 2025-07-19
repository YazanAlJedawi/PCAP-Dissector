from ssh_Dissector import *
from http_Dissector import *
from stats_collector import *
from commands_handler import *

def main():

    try:
        if (sys.argv[1]):
            mode=sys.argv[1]
    except:
        print(interface())
        return

    if (sys.argv[1]=="logo"):
        print_logo()
        return

    if (sys.argv[1]=="help"):
        print(help_msg_func())
        return


    elif mode == "http-analysis":
        if len(sys.argv) != 3:
            print("Usage: python Dissector.py http-analysis <capture.pcap>")
            return
        activate_http_analysis(sys.argv[2])
        return

    
    elif mode == "ssh-analysis":
        if len(sys.argv) != 3:
            print("Usage: python Dissector.py ssh-analysis <capture.pcap>")
            return
        activate_ssh_analysis(sys.argv[2])
        return

   
    
    elif (sys.argv[1]=="stats"):
        if len(sys.argv) != 3:
            print("Usage: python Dissector.py stats <capture.pcap>")
            return
        activate_stats_collection(sys.argv[2])
        return
    
    


main()
