# Script:   pcap_modules.py
# Desc:     Supporting Classes for PCAP_Analyser
# Author:   Jacob Connell Nov 2019
# Note: Run setup.py before use!

import datetime
import os
import re
import socket
import time
import dpkt
import statistics as stats
import networkx as nx
import numpy as np
import simplekml
import geoip2.database
import matplotlib.pyplot as plt
from prettytable import PrettyTable
from core_modules import *


class ImageTable:
    '''Creates an object resposiable for analysis and display of image data'''
    def __init__(self):
        self.image_table = PrettyTable(['From', 'To', 'Type', 'Name', 'URI'])
        self.image_summary = PrettyTable(['Image Type', 'Total'])
        self.gif_count = 0
        self.jpg_count = 0
        self.png_count = 0
        self.URIs = []

    def check_packet(self, ip):
        '''Analyses current packet for image URIs'''
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            self.tcp = ip.data
            self.src = socket.inet_ntoa(ip.src)
            self.dst = socket.inet_ntoa(ip.dst)
            try:
                self.http = dpkt.http.Request(self.tcp.data)
                if self.http.method == 'GET':
                    self.uri = (self.http.headers['host'] + self.http.uri\
                                ).lower()
                    if '.gif' in self.uri:
                        self.image_table.add_row(
                            [self.src, self.dst, 'gif', re.findall(\
                                '[a-zA-Z0-9_.+-]+.gif', self.uri)[0],
                             "http://" + self.uri[:100]])
                        self.URIs.append(self.uri)
                        self.gif_count += 1
                    if '.jpg' in self.uri:
                        self.image_table.add_row(
                            [self.src, self.dst, 'jpg', re.findall(\
                                '[a-zA-Z0-9_.+-]+.jpg', self.uri)[0],
                             "http://" + self.uri[:100]])
                        self.URIs.append(self.uri)
                        self.jpg_count += 1
                    if '.jpeg' in self.uri:
                        self.image_table.add_row(
                            [self.src, self.dst, 'jpg', re.findall(\
                                '[a-zA-Z0-9_.+-]+.jpeg', self.uri)[0],
                             "http://" + self.uri[:100]])
                        self.URIs.append(self.uri)
                        self.jpg_count += 1
                    if '.png' in self.uri:
                        self.image_table.add_row(
                            [self.src, self.dst, 'png', re.findall(\
                                '[a-zA-Z0-9_.+-]+.png', self.uri)[0],
                             "http://" + self.uri[:100]])
                        self.URIs.append(self.uri)
                        self.png_count += 1
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                pass

    def output_summary(self):
        '''Create a summart table using the total counter and outputs'''
        self.image_summary.add_row(['JPG', self.jpg_count])
        self.image_summary.add_row(['GIF', self.gif_count])
        self.image_summary.add_row(['PNG', self.png_count])
        print(self.image_summary)

    def output(self, file_path):
        '''Outputs the image tables and saves full URIs to a json file'''
        print(self.image_table)
        self.output_summary()
        print("Full URIs Exported to file in directory.")
        save(self.URIs, 'Full URIs', file_path)


class FindEmails:
    '''Parses PCAP file for Emails in the From and To fields'''
    def __init__(self):
        self.my_emails = []

    def check_emails(self, ip):
        '''Analyses current packet for emails matching syntax
        and then appends found emails to an instance array'''
        try:
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                self.mail = ""
                try:
                    self.mail = ip.data.data.decode('UTF-8')
                except:
                    pass
            '''RegEx adapted from https://www.tutorialspoint.com/
                Extracting-email-addresses-using-regular-
                expressions-in-Python'''
            self.mail_to = (re.findall(\
                r"((TO: <)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+>)", \
                self.mail))
            self.mail_from = (re.findall(\
                r"(FROM: <[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+>)", \
                self.mail))
            if len(self.mail_to) != 0:
                for self.emails in self.mail_to:
                    for self.email in self.emails:
                        self.stripped = re.findall(\
                            r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"\
                            , self.email)
                        if len(self.stripped) != 0:
                            if f'To:{self.stripped[0]}' not in self.my_emails:
                                self.my_emails.append(f'To:{str(self.stripped[0])}')
            if len(self.mail_from) != 0:
                for self.email in self.mail_from:
                    self.stripped = re.findall(\
                        r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", \
                        self.email)
                    if len(self.stripped) != 0:
                        if f'From:{self.stripped[0]}' not in self.my_emails:
                            self.my_emails.append(f'From:{str(self.stripped[0])}')
        except ValueError:
            pass

    def output(self):
        '''Outputs emails in instance array to console'''
        self.email_table = PrettyTable(["Unique Emails"])
        for self.address in self.my_emails:
            self.email_table.add_row([self.address])
        print(self.email_table)


class Packet_Summary:
    '''Parses file for specific packet types
        and calculates statistics based on them'''
    def __init__(self):
        self.tcp_stats = {'counter': 0, 'total_length': 0, 'mean_length': 0,\
                          'min_ts': 0, 'max_ts': 0}
        self.udp_stats = {'counter': 0, 'total_length': 0, 'mean_length': 0,\
                          'min_ts': 0, 'max_ts': 0}
        self.igmp_stats = {'counter': 0, 'total_length': 0, 'mean_length': 0,\
                           'min_ts': 0, 'max_ts': 0}
        self.error_count = 0
        self.counter = 0

    def sort_packet(self, ip, buf, ts):
        '''Sorts current packet by checking the packet type'''
        self.counter += 1
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            self.tcp = ip.data
            self.tcp_stats['total_length'] += len(buf)
            self.tcp_stats['counter'] += 1
            if ts > self.tcp_stats['max_ts']:
                self.tcp_stats['max_ts'] = ts
            if ts < self.tcp_stats['min_ts'] or self.tcp_stats['min_ts'] == 0:
                self.tcp_stats['min_ts'] = ts

        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            self.udp = ip.data
            self.udp_stats['total_length'] += len(buf)
            self.udp_stats['counter'] += 1
            if ts > self.udp_stats['max_ts']:
                self.udp_stats['max_ts'] = ts
            if ts < self.udp_stats['min_ts'] or self.udp_stats['min_ts'] == 0:
                self.udp_stats['min_ts'] = ts

        elif ip.p == dpkt.ip.IP_PROTO_IGMP:
            self.igmp = ip.data
            self.igmp_stats['total_length'] += len(buf)
            self.igmp_stats['counter'] += 1
            if ts > self.igmp_stats['max_ts']:
                self.igmp_stats['max_ts'] = ts
            if ts < self.igmp_stats['min_ts'] or self.igmp_stats['min_ts'] == 0:
                self.igmp_stats['min_ts'] = ts
        else:
            self.error_count += 1

    def output(self):
        '''Summarises Calculations and Outputs'''
        print("\n[!] Loading Packet Summary Table...")
        time.sleep(1)
        print("[!] Displaying Packet Summary Table...\n")
        try:
            self.tcp_stats['mean_length'] = round(self.tcp_stats['total_length']\
                                                  / self.tcp_stats['counter'])
        except ZeroDivisionError:
            self.tcp_stats['mean_length'] = 0
        print(
            f'\nPacket Type: TCP\n\tPacket Count: {self.tcp_stats["counter"]}\n\tMean Length: {self.tcp_stats["mean_length"]}')
        print("\tMinimum Timestamp: " + str(
            datetime.datetime.utcfromtimestamp(self.tcp_stats["min_ts"])) \
              + "\n\tMaximum Timestamp: " + str(
            datetime.datetime.utcfromtimestamp(self.tcp_stats["max_ts"])))
        try:
            self.udp_stats['mean_length'] = round(self.udp_stats['total_length']\
                                                  / self.udp_stats['counter'])
        except ZeroDivisionError:
            self.udp_stats['mean_length'] = 0
        print(
            f'\nPacket Type: UDP\n\tPacket Count: {self.udp_stats["counter"]}\n\tMean Length: {self.udp_stats["mean_length"]}')
        print("\tMinimum Timestamp: " + str(
            datetime.datetime.utcfromtimestamp(self.udp_stats["min_ts"]))\
              + "\n\tMaximum Timestamp: " + str(
            datetime.datetime.utcfromtimestamp(self.udp_stats["max_ts"])))
        try:
            self.igmp_stats['mean_length'] = round(self.igmp_stats['total_length']\
                                                   / self.igmp_stats['counter'])
        except ZeroDivisionError:
            self.igmp_stats['mean_length'] = 0
        print(
            f'\nPacket Type: IGMP\n\tPacket Count: {self.igmp_stats["counter"]}\n\tMean Length: {self.igmp_stats["mean_length"]}')
        print("\tMinimum Timestamp: " + str(
            datetime.datetime.utcfromtimestamp(self.igmp_stats["min_ts"]))\
              + "\n\tMaximum Timestamp: " + str(
            datetime.datetime.utcfromtimestamp(self.igmp_stats["max_ts"])))
        print(f'\n{self.error_count} unrecognised packets')
        print(self.counter)


class Flow_Chart:
    '''A class responsable for generating
    the flow chart from a list of timestamps'''
    def __init__(self):
        self.timestamps = []

    def add_timestamp(self, ts):
        '''Appends a timestamp to to instance array'''
        self.timestamps.append(ts)

    def output(self, file_path):
        '''Calculates line chart, displays and saves to file'''
        print("\n[!] Creating Data Flow Line Chart...")
        self.timestamps = sorted(self.timestamps)
        self.relative_times = []
        self.first_time = datetime.datetime.fromtimestamp(self.timestamps[0])
        for self.i in self.timestamps:
            self.temp_time = datetime.datetime.fromtimestamp(self.i) - \
                             datetime.datetime.fromtimestamp(
                self.timestamps[0])
            self.temp_time = float(str(self.temp_time.seconds) + '.' + \
                                   str(self.temp_time.microseconds))
            self.relative_times.append(self.temp_time)
        self.relative_times = sorted(self.relative_times)
        self.interval_period = 20
        self.interval = self.interval_period
        self.mydict = {}
        self.intervals = []
        self.timestamp = self.first_time.strftime("%H:%M:%S")
        for self.i in self.relative_times:
            if self.i < self.interval:
                if self.mydict.get(self.timestamp) is None:
                    self.mydict[self.timestamp] = [self.i]
                else:
                    self.mydict[self.timestamp].append(self.i)
            else:
                self.timestamp = (self.first_time +
                    datetime.timedelta(seconds=round(
                        self.interval, 3))).strftime(
                    "%H:%M:%S")
                self.interval = self.interval + self.interval_period
                if self.mydict.get(self.timestamp) is None:
                    self.mydict[self.timestamp] = [self.i]
                else:
                    self.mydict[self.timestamp].append(self.i)
        self.x_values = []
        self.y_values = []
        for self.k in self.mydict:
            self.mydict[self.k] = len(self.mydict[self.k])
            self.x_values.append(self.k)
            self.y_values.append(self.mydict[self.k])
        self.threshold = stats.mean(self.y_values) + \
                         (stats.stdev(self.y_values) * 2)
        self.objects = self.x_values
        self.y_pos = np.arange(len(self.objects))
        ax = plt.subplot(111)
        ax.plot(self.x_values, self.y_values, label='Traffic')
        plt.xticks(self.y_pos, self.objects, rotation=90)
        plt.ylabel('Packets')
        plt.xlabel('TimeStamp')
        plt.title('Packet Flow')
        ax.axhline(y=self.threshold, linewidth=1, color='k', label='Threshold')
        ax.legend()
        plt.tight_layout()
        print("[!] Saving Data Flow Line Chart...")
        try:
            plt.savefig(f'{file_path}/Packet Flow Chart.png', pad_inches=0.5)
        except:
            print("[!]Error - Folder not found. File not saved.")
        print("[!] Displaying Data Flow Line Chart...")
        plt.show()


class Traffic_Table:
    '''Hosts a set of tables displaying IP traffics'''
    def __init__(self):
        self.addresses = {}
        self.traffic_table = PrettyTable(['Sent', 'Received', 'Address', 'Total'])
        self.connection_table = PrettyTable(['Source', 'Destination', 'Connections'])

    def add_address(self, ip):
        '''Adds the addresses from the current packet to the dictionary'''
        self.src = socket.inet_ntoa(ip.src)
        self.dst = socket.inet_ntoa(ip.dst)
        if self.addresses.get(self.src) is None:
            self.addresses[self.src] = [1, 0]
        else:
            self.addresses[self.src][0] = self.addresses[self.src][0] + 1

        if self.addresses.get(self.dst) is None:
            self.addresses[self.dst] = [0, 1]
        else:
            self.addresses[self.dst][1] = self.addresses[self.dst][1] + 1

    def output_summary(self, file_path):
        '''Outputs the table from the dictionary data'''
        print("\n[!] Creating Data Traffic Table...")
        for key, self.value in sorted(self.addresses.items(), \
                            key=lambda item: item[1][0] + item[1][1], reverse=True):
            self.traffic_table.add_row([self.value[0], self.value[1], \
                                        key, self.value[0] + self.value[1]])
        print("[!] Displaying Data Traffic Table...\n")
        print(self.traffic_table)
        print("\n[!] Saving Data Traffic Table...")
        save(self.addresses, 'IP Traffic', file_path)

    def output_connections(self, connections, file_path):
        '''Outputs the connections from the passed dictionary'''
        print("\n[!] Creating Data Flow Table...")
        for k in connections:
            for v in connections[k]:
                self.connection_table.add_row([k, v, connections[k][v]])
        print("[!] Displaying Data Flow Table...\n")
        print(self.connection_table)
        print("\n[!] Saving Data Flow Table...")
        save(connections, 'IP Flow', file_path)


class Node_Graph:
    '''Hosts the data and contruction methods for the node graph'''
    def __init__(self):
        self.network_map = {}

    def add_connection(self, ip):
        '''Sorts IP from given packet'''
        self.src = socket.inet_ntoa(ip.src)
        self.dst = socket.inet_ntoa(ip.dst)
        if self.network_map.get(self.src) is None:
            self.network_map[self.src] = {}
        if self.network_map[self.src].get(self.dst) is None:
            self.network_map[self.src][self.dst] = 1
        else:
            self.network_map[self.src][self.dst] = self.network_map[self.src][self.dst] + 1

    def output(self, file_path):
        '''Creates, displays and saves graph'''  
        print("\n[!] Creating Network Node Graph...")
        self.g = nx.MultiDiGraph(
            (k, v, {'weight': weight}) for k, vs in self.network_map.items()\
            for v, weight in vs.items())
        self.pos = nx.shell_layout(self.g)
        nx.draw(self.g, self.pos, with_labels=True, linewidths=4)
        nx.draw_networkx_edge_labels(self.g, self.pos, \
                                     with_labels=True, alpha=0.5)
        print("[!] Saving Network Node Graph...")
        try:
            plt.savefig(f'{file_path}/IP Network Map.png', pad_inches=0.5)
        except:
            print("[!]Error - Folder not found. File not saved.")
        print("[!] Displaying Network Node Graph...")
        plt.show()

    def get_dict(self):
        '''Returns network map data dictionary'''
        return self.network_map


class KML_File:
    '''KML generator'''
    def __init__(self):
        self.Distinct_IP_List = []
        self.location_data = {}

    def add_addresses(self, ip):
        '''Rips IPs from passed packet'''
        self.src = socket.inet_ntoa(ip.src)
        self.dst = socket.inet_ntoa(ip.dst)
        if self.src not in self.Distinct_IP_List:
            self.Distinct_IP_List.append(self.src)
        if self.dst not in self.Distinct_IP_List:
            self.Distinct_IP_List.append(self.dst)

    def output(self, file_path):
        '''Outputs KML file to directory and opens in Google Earth'''
        download_geo_db()
        print("\n[!] Downloading GEO DB...")
        self.kml = simplekml.Kml()
        self.error_count = 0
        try: #Opens DB with a dynamic file path
            self.directory = ("./GeoLite2-City.tar/" + os.listdir("./GeoLite2-City.tar/")[0] + "/")
            print("[!] Unpacking GEO DB...")
            self.reader = geoip2.database.Reader(f'{self.directory}/GeoLite2-City.mmdb')
        except:
            print("[!] Database Error")
        print("[!] Looking-up IPs...")
        for self.ip in self.Distinct_IP_List:
            try:
                self.rec = self.reader.city(self.ip)
                if self.rec.city.name is None:
                    self.city = ""
                else:
                    self.city = self.rec.city.name
                self.location_data[self.ip] = {"country": self.rec.country.name, "city": self.city,
                                               "longitude": self.rec.location.longitude,
                                               "latitude": self.rec.location.latitude}
            except:
                self.error_count += 1

        for self.key in self.location_data:
            self.pnt = self.kml.newpoint(name=self.key, coords=[
                (self.location_data[self.key]["longitude"], \
                 self.location_data[self.key]["latitude"])], description=( 
                    self.location_data[self.key]["country"] \
                    + self.location_data[self.key]["city"]))
        try:
            self.kml.save(f'{file_path}/GeoIPs.kml')
            print(f'[!] Location data not available for {self.error_count} IPs')
            print('[!] Opening file in default app (Google Earth)')
            os.startfile(f'{file_path}/GeoIPs.kml')
        except:
            print("[!] Error - Folder Not Found")


# Boiler Plate
if __name__ == '__main__':
    print("[!]Nothing to run here.")
