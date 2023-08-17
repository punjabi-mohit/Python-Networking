import tkinter as tk
import tkinter.messagebox
from tkinter import ttk

import scapy.all as scapy
import threading
import collections, signal
import datetime

def start_button():
    print('Start Button Clicked')
    global thread
    global should_we_stop
    global subdomain

    subdomain = subdomain_entry.get()

    if (thread is None) or (not thread.is_alive()):
        should_we_stop = False
        thread = threading.Thread(target=sniffing)
        thread.start()

def stop_button():
    print('Stop Button Clicked')
    global should_we_stop
    should_we_stop = True
    quit()

def sniffing():
    scapy.sniff(prn=find_ips, stop_filter=stop_sniffing,)

def stop_sniffing(packet):
    global should_we_stop
    return should_we_stop

src_ip_dict_temp = {}
global tree1

def find_ips(packet):
    global src_ip_dict
    global tree

    global subdomain
    global should_we_stop

    if 'IP' in packet:
        if 'TCP' in packet:
            if len(src_ip_dict_temp) >= 1:
                dt = datetime.datetime.now()
                seq = dt.strftime("%H%M%S")
                per_second = int(seq) + 1
                for i in list(src_ip_dict_temp.items()):
                    if int(i[1][1]) <= per_second - 2:
                        del src_ip_dict_temp[i[0]]
                    else:
                        sum1 = 0
                        sum1 = sum1 + int(i[1][0])
                        if sum1 >= 100:
                            open_popup(str(i[0]))
                            should_we_stop = True
                            stop_sniffing(packet)

            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst

            if src_ip[0:len(subdomain)] == subdomain and dst_ip == "192.168.0.102":
                count = 0
                if src_ip not in (src_ip_dict and src_ip_dict_temp):
                    dt = datetime.datetime.now()
                    seq = dt.strftime("%H%M%S")
                    src_ip_dict[src_ip] = [count + 1, seq]
                    src_ip_dict_temp[src_ip] = [count + 1, seq]
                else:
                    count1 = src_ip_dict[src_ip][0]
                    src_ip_dict[src_ip][0] = count1 + 1
                    dt = datetime.datetime.now()
                    seq = dt.strftime("%H%M%S")
                    src_ip_dict[src_ip][1] = seq
                    src_ip_dict_temp[src_ip][0] = count1 + 1
                    src_ip_dict_temp[src_ip][1] = seq
                print(src_ip_dict_temp)

            def getlist(src_ip_dict_temp):
                global list1
                for key, values in src_ip_dict_temp.items():
                    if values[0] >= 20 and key not in list1:
                        list1.append(key)
                        tree1.insert('', index=tk.END, text=key)
                        tree1.pack(fill=tk.X)
                        stop_sniffing(packet)
                        break
                return list1

            print(getlist(src_ip_dict_temp))

            row = tree.insert('', index=tk.END, text=src_ip)
            tree.insert(row, tk.END, text=dst_ip)
            tree.pack(fill=tk.X)

thread = None
should_we_stop = True
subdomain = ''
list1 = []

src_ip_dict = {}

root = tk.Tk()

root.geometry('500x500')
root.title('Packet Sniffer')

tk.Label(root, text='Python Packet Sniffer', font="Arial 24 bold").pack()
tk.Label(root, text="Enter the IP address", font="Arial 16 bold").pack()

subdomain_entry = tk.Entry(root)
subdomain_entry.pack(ipady=5, ipadx=58, pady=10)

tree = ttk.Treeview(root, height=300)
tree.column('#0')

top = tk.Toplevel(root)
top.geometry("900x200")
tk.Label(top, text="Possibility of Attack By IP's below!!!!", font="Arial 16 bold").pack()
tree1 = ttk.Treeview(top, height=300)
top.title("Alert Window")

button_frame = tk.Frame(root)

tk.Button(button_frame, text="Start Sniffing", command=start_button, width=15, font="Arial 10 bold").pack(side=tk.LEFT)
tk.Button(button_frame, text="Stop Sniffing", command=stop_button, width=15, font="Arial 10 bold").pack(side=tk.LEFT)
button_frame.pack(side=tk.BOTTOM, pady=10)


def open_popup(i):
    top = tk.Toplevel(root)
    top.geometry("750x250")
    top.title("Alert Window")
    tk.Label(top, text="Alert! Block the IP  " + i + "\n There is a DDOS attack!!!!", font='Helvetica 14 bold').pack(
        pady=20)


root.mainloop()
