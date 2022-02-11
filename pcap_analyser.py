# Script:   pcap_analyser.py
# Desc:     Script to parse a PCAP File
# Author:   Jacob Connell Nov 2019
# Note: Run setup.py before use!

import os
from tkinter import *
from tkinter import messagebox
from tkinter.filedialog import askopenfilename
import dpkt
from parse_modules import *


class Window(object):
    '''Creates and displays GUI'''
    def __init__(self, window):

        self.window = window

        self.window.wm_title("PCAP Analyser")

        l1 = Label(window, text="PCAP File")
        l1.grid(row=0, column=0)

        self.file_text = StringVar()
        self.file1 = Entry(window, textvariable=self.file_text, width=60)
        self.file1.grid(row=0, column=1)

        b1 = Button(window, text="Browse", width=12, command=self.find_file)
        b1.grid(row=0, column=2)

        l2 = Label(window, text="New Directory Name")
        l2.grid(row=1, column=0, padx=30)

        self.folder_text = StringVar()
        self.folder1 = Entry(window, textvariable=self.folder_text, width=20)
        self.folder1.grid(row=2, column=0)

        b3 = Button(window, text="Analyses File", width=12,
                    command=self.go_command)
        b3.grid(row=2, column=2)

    def find_file(self):
        '''Opens file browser for PCAP'''
        name = askopenfilename(initialdir="C:",
                               filetypes=(("PCAP", "*.pcap"),
                            ("All Files", "*.*")), title="Choose a file.")
        self.file_text.set(name)

    def go_command(self):
        '''Runs the main program'''
        if (len(self.file_text.get())) > 0:
            if (len(self.folder_text.get())) > 0:

                run_program(self.file_text.get(), self.folder_text.get())
            else:
                messagebox.showwarning("Error", "Error - Invalid Folder Name")
        else:
            messagebox.showwarning("Error", "Error - Invalid File Path!")


def hold():
    '''Holds the program to wait for user input'''
    wait = input("Press Enter to Continue")

    
def run_program(pcapfile, folder_name):
    '''Takes the PCAP path as an input and loops through each
    packet - sending data to the relivant objects'''
    try:
        window.destroy()
        print("[!] Creating Directory...")
        create_directory(folder_name)
        cwd = os.getcwd()
        file_path = os.path.join(cwd, f'{folder_name}')
        print(f'[!] Opening PCAP File: {pcapfile}...')
        f = open(pcapfile, 'rb')
        pcap = dpkt.pcap.Reader(f)

        my_images = ImageTable()
        email_addresses = FindEmails()
        my_summary = Packet_Summary()
        my_line_chart = Flow_Chart()
        my_traffic = Traffic_Table()
        my_network_graph = Node_Graph()
        my_map = KML_File()

        error_count = 0

        print("[!] Analysing File...")
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                my_line_chart.add_timestamp(ts)
                my_traffic.add_address(ip)
                my_network_graph.add_connection(ip)
                my_map.add_addresses(ip)
                email_addresses.check_emails(ip)
                my_images.check_packet(ip)
                my_summary.sort_packet(ip, buf, ts)

            except:
                error_count += 1
                pass

        my_images.output(file_path)
        hold()
        email_addresses.output()
        hold()
        my_summary.output()
        hold()
        my_traffic.output_summary(file_path)
        hold()
        my_traffic.output_connections(my_network_graph.get_dict(), file_path)
        hold()
        my_network_graph.output(file_path)
        hold()
        my_line_chart.output(file_path)
        hold()
        my_map.output(file_path)

    except:
        print("Error Opening File")


# Boiler Plate
if __name__ == '__main__':
    window = Tk()
    Window(window)
    window.mainloop()
