# Script:   core_modules.py
# Desc:     Script to support PCAP Parse Script
# Author:   Jacob Connell Nov 2019
# Note: Run setup.py before use!

import json
import os
import tarfile
import urllib.request
import shutil
from parse_modules import *


def download_geo_db():
    '''Downloads and unzips GEODB for code, adapted
        from https://www.programcreek.com/python/
        example/81585/urllib.request.urlretrieve
        (Example 5)'''
    url = 'https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz'
    file_tmp = urllib.request.urlretrieve(url, filename=False)[0]
    base_name = os.path.basename(url)
    file_name, file_extension = os.path.splitext(base_name)
    tar = tarfile.open(file_tmp)
    tar.extractall(file_name)


def create_directory(file_name):
    '''Creates new folder a removes existing one
       Adapted from https://thispointer.com/
       python-how-to-delete-a-directory-
       recursively-using-shutil-rmtree/'''
    cwd = os.getcwd()
    new_dir = os.path.join(cwd, f'{file_name}')
    if os.path.exists(new_dir):
        shutil.rmtree(new_dir, ignore_errors=True)
    if not os.path.exists(new_dir):
        os.mkdir(new_dir)


def save(data_dict, filename, file_path):
    '''Saves data to json file'''
    with open(f'{file_path}/{filename}.json', 'w') as json_file:
        json.dump(data_dict, json_file)
    json_file.close()


# Boiler Plate
if __name__ == '__main__':
    print("[!]Nothing to run here.")
