# Script:   setup.py
# Desc:     installs required modules for PCAP Analysis
#           Admin rights required.
# Author:   Jacob Connell Nov 2019

# Note: Run setup.py before use!


def main():
    import subprocess
    run = subprocess.Popen(['moduleinstall.cmd'])


# Boiler Plate
if __name__ == '__main__':
    print("[!]Commanding Module Installs with Pip. Please Wait...")
    main()
