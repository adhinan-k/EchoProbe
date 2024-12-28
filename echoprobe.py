#!/usr/bin/env python3

import subprocess
import time
from datetime import datetime
import logging
import sys
import os
import signal
from scapy.all import *
import threading

class EchoProbe:
    def __init__(self):
        self.networks = {}
        self.attackers = set()
        self.is_monitoring = False
        self.interface = None
        self.channel = 1
        self.last_update_time = time.time()
        self.screen_buffer = ""  # Add screen buffer
        self.setup_logging()
        signal.signal(signal.SIGINT, self.signal_handler)

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        self.logger = logging.getLogger(__name__)

    def check_root(self):
        if os.geteuid() != 0:
            print("\033[1;31m[!] This script must be run as root!\033[0m")
            sys.exit(1)

    def find_wireless_interface(self):
        try:
            # First try to find monitor mode interfaces
            result = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT, text=True)
            interfaces = []
            for line in result.split('\n'):
                if 'Mode:Monitor' in line:
                    return line.split()[0]
                elif 'IEEE 802.11' in line:
                    interfaces.append(line.split()[0])
            
            # If no monitor mode interface found, return first wireless interface
            if interfaces:
                return interfaces[0]
            else:
                print("\033[1;31m[!] No wireless interfaces found!\033[0m")
                print("\033[1;33m[*] Please make sure your wireless adapter is connected and supported\033[0m")
                sys.exit(1)
        except Exception as e:
            print(f"\033[1;31m[!] Error finding wireless interface: {str(e)}\033[0m")
            sys.exit(1)

    def setup_monitor_mode(self):
        try:
            self.interface = self.find_wireless_interface()
            print(f"\033[1;32m[+] Found wireless interface: {self.interface}\033[0m")

            # Kill interfering processes
            print("\033[1;33m[*] Killing interfering processes...\033[0m")
            subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Stop NetworkManager
            print("\033[1;33m[*] Stopping NetworkManager...\033[0m")
            subprocess.run(['systemctl', 'stop', 'NetworkManager'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Try different methods to enable monitor mode
            try:
                # Method 1: Using airmon-ng
                subprocess.run(['airmon-ng', 'start', self.interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.interface = f"{self.interface}mon"
            except:
                try:
                    # Method 2: Using iwconfig
                    subprocess.run(['ifconfig', self.interface, 'down'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(['iwconfig', self.interface, 'mode', 'monitor'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(['ifconfig', self.interface, 'up'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except:
                    print("\033[1;31m[!] Failed to enable monitor mode\033[0m")
                    return False

            # Verify monitor mode
            result = subprocess.check_output(['iwconfig', self.interface], stderr=subprocess.STDOUT, text=True)
            if 'Mode:Monitor' in result:
                print(f"\033[1;32m[+] Successfully enabled monitor mode on {self.interface}\033[0m")
                return True
            else:
                print("\033[1;31m[!] Failed to verify monitor mode\033[0m")
                return False

        except Exception as e:
            print(f"\033[1;31m[!] Error setting up monitor mode: {str(e)}\033[0m")
            print("\033[1;33m[*] Tips:")
            print("   - Make sure you have a compatible wireless adapter")
            print("   - Ensure airmon-ng is installed")
            print("   - Try running with sudo privileges")
            print("   - Check if your wireless card supports monitor mode\033[0m")
            return False

    def packet_handler(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                bssid = pkt.addr2
                try:
                    ssid = pkt.info.decode('utf-8')
                except:
                    ssid = "Unknown"
                
                # Update or add network
                signal_strength = -(256-ord(pkt.notdecoded[-4:-3]))
                current_time = time.time()
                
                if bssid not in self.networks:
                    self.networks[bssid] = {
                        'ssid': ssid,
                        'channel': int(ord(pkt[Dot11Elt:3].info)),
                        'signal': signal_strength,
                        'suspicious_activity': 0,
                        'first_seen': current_time,
                        'last_seen': current_time,
                        'beacons': 1,
                        'data_packets': 0
                    }
                else:
                    self.networks[bssid].update({
                        'signal': signal_strength,
                        'last_seen': current_time,
                        'beacons': self.networks[bssid]['beacons'] + 1
                    })

            # Data packets
            elif pkt.type == 2:
                bssid = pkt.addr1 if pkt.addr1 in self.networks else pkt.addr2
                if bssid in self.networks:
                    self.networks[bssid]['data_packets'] += 1

            # Deauthentication detection
            elif pkt.type == 0 and pkt.subtype == 12:
                if pkt.addr2 not in self.attackers:
                    self.attackers.add(pkt.addr2)
                    if pkt.addr1 in self.networks:
                        self.networks[pkt.addr1]['suspicious_activity'] += 1

    def signal_handler(self, sig, frame):
        print("\n\033[1;33m[*] Shutting down EchoProbe...\033[0m")
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        if self.interface:
            try:
                # Remove 'mon' suffix if present
                original_interface = self.interface.replace('mon', '')
                
                # Try different cleanup methods
                try:
                    subprocess.run(['airmon-ng', 'stop', self.interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except:
                    try:
                        subprocess.run(['ifconfig', self.interface, 'down'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        subprocess.run(['iwconfig', self.interface, 'mode', 'managed'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        subprocess.run(['ifconfig', self.interface, 'up'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except:
                        pass

                # Restart NetworkManager
                subprocess.run(['systemctl', 'start', 'NetworkManager'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("\033[1;32m[+] Network interface restored\033[0m")
            except Exception as e:
                print(f"\033[1;31m[!] Cleanup error: {str(e)}\033[0m")

    def get_signal_icon(self, signal_strength):
        if signal_strength >= -50:
            return "█"
        elif signal_strength >= -60:
            return "▇"
        elif signal_strength >= -70:
            return "▅"
        else:
            return "▂"

    def get_signal_quality(self, signal_strength):
        if signal_strength >= -50:
            return "Excellent"
        elif signal_strength >= -60:
            return "Very Good"
        elif signal_strength >= -70:
            return "Good    "
        elif signal_strength >= -80:
            return "Fair    "
        elif signal_strength >= -90:
            return "Poor    "
        else:
            return "Very Poor"

    def print_status(self):
        # Colors definition
        cyan = "\033[1;36m"
        magenta = "\033[1;35m"
        blue = "\033[1;34m"
        yellow = "\033[1;33m"
        green = "\033[1;32m"
        red = "\033[1;31m"
        white = "\033[1;37m"
        reset = "\033[0m"
        
        # Clear screen buffer
        output = []
        
        # Banner
        output.extend([
            f"{cyan}███████╗ ██████╗██╗  ██╗ ██████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗",
            f"{cyan}██╔════╝██╔════╝██║  ██║█���╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝",
            f"{cyan}█████╗  ██║     ███████║██║   ██║██████╔╝██████╔╝██║   ██║██████╔╝█████╗  ",
            f"{cyan}██╔══╝  ██║     ██╔══██║██║   ██║██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  ",
            f"{cyan}███████╗╚██████╗██║  ██║╚██████╔╝██║     ██║  ██║╚██████╔╝██████╔╝███████╗",
            f"{cyan}╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝{reset}",
            ""
        ])

        # Channel indicator
        output.append(f"{yellow}CH {self.channel}{reset} {white}(Press Ctrl+C to exit){reset}\n")

        # Calculate maximum widths for each column based on content
        max_ssid_width = max(len(data['ssid']) for data in self.networks.values()) if self.networks else 12
        max_ssid_width = max(max_ssid_width, 12)  # Minimum width of 12 for "SSID" header
        
        max_bssid_width = 17  # BSSID is always 17 chars
        max_signal_width = 7   # Signal format "-XX" + icon
        max_ch_width = max(len(str(data['channel'])) for data in self.networks.values()) if self.networks else 4
        max_ch_width = max(max_ch_width, 4)  # Minimum width of 4 for "CH" header
        
        max_bcn_width = max(len(str(data['beacons'])) for data in self.networks.values()) if self.networks else 4
        max_bcn_width = max(max_bcn_width, 4)  # Minimum width of 4 for "BCN" header
        
        max_data_width = max(len(str(data['data_packets'])) for data in self.networks.values()) if self.networks else 4
        max_data_width = max(max_data_width, 4)  # Minimum width of 4 for "Data" header
        
        status_width = 11  # Fixed width for status column
        quality_width = 14  # Width for the longest text ("Very Poor") + bars

        # Create dynamic header
        header_line = (
            f"{blue}┌{'─' * (max_ssid_width + 2)}┬{'─' * (max_bssid_width + 2)}"
            f"┬{'─' * (max_signal_width + 2)}┬{'─' * (max_ch_width + 2)}"
            f"┬{'─' * (max_bcn_width + 2)}┬{'─' * (max_data_width + 2)}"
            f"┬{'─' * (status_width + 2)}┬{'─' * (quality_width + 2)}┐{reset}"
        )

        header_titles = (
            f"{blue}│{yellow} {'SSID'.ljust(max_ssid_width)} {blue}│"
            f"{yellow} {'BSSID'.ljust(max_bssid_width)} {blue}│"
            f"{yellow} {'Signal'.ljust(max_signal_width)} {blue}│"
            f"{yellow} {'CH'.ljust(max_ch_width)} {blue}│"
            f"{yellow} {'BCN'.ljust(max_bcn_width)} {blue}│"
            f"{yellow} {'Data'.ljust(max_data_width)} {blue}│"
            f"{yellow} {'Status'.ljust(status_width)} {blue}│"
            f"{yellow} {'Signal Quality'.ljust(quality_width)} {blue}│{reset}"
        )

        separator_line = (
            f"{blue}├{'─' * (max_ssid_width + 2)}┼{'─' * (max_bssid_width + 2)}"
            f"┼{'─' * (max_signal_width + 2)}┼{'─' * (max_ch_width + 2)}"
            f"┼{'─' * (max_bcn_width + 2)}┼{'─' * (max_data_width + 2)}"
            f"┼{'─' * (status_width + 2)}┼{'─' * (quality_width + 2)}┤{reset}"
        )

        output.extend([header_line, header_titles, separator_line])

        # Network entries with dynamic widths
        for bssid, data in sorted(self.networks.items(), key=lambda x: x[1]['signal'], reverse=True):
            is_attacked = data['suspicious_activity'] > 5
            signal_strength = int(data['signal'])
            
            status = f"{red}⚠ JAMMED{reset}" if is_attacked else f"{green}✓ NORMAL{reset}"
            signal_quality = self.get_signal_quality(signal_strength)
            quality_color = green if signal_strength >= -60 else yellow if signal_strength >= -80 else red
            
            # Dynamic width formatting
            ssid = data['ssid'][:max_ssid_width].ljust(max_ssid_width)
            bssid_short = bssid[:max_bssid_width].ljust(max_bssid_width)
            signal_str = f"{self.get_signal_icon(signal_strength)}{str(signal_strength)}".ljust(max_signal_width)
            channel = str(data['channel']).ljust(max_ch_width)
            beacons = str(data['beacons']).ljust(max_bcn_width)
            data_pkts = str(data['data_packets']).ljust(max_data_width)
            status_str = status.ljust(status_width)

            # Format signal quality with consistent width
            quality_text = self.get_signal_quality(signal_strength)
            if signal_strength >= -50:
                quality_bars = "▰▰▰▰▰"
            elif signal_strength >= -60:
                quality_bars = "▰▰▰▰▱"
            elif signal_strength >= -70:
                quality_bars = "▰▰▰▱▱"
            elif signal_strength >= -80:
                quality_bars = "▰▰▱▱▱"
            elif signal_strength >= -90:
                quality_bars = "▰▱▱▱▱"
            else:
                quality_bars = "▱▱▱▱▱"

            quality_str = f"{quality_color}{quality_text} {quality_bars}{reset}"

            output.append(
                f"{blue}│{white} {ssid} {blue}│{white} {bssid_short} {blue}│{white} "
                f"{signal_str} {blue}│{white} {channel} {blue}│{white} {beacons} {blue}│{white} "
                f"{data_pkts} {blue}│{reset} {status_str} {blue}│ {quality_str} {blue}│{reset}"
            )

        # Bottom border with dynamic widths
        bottom_line = (
            f"{blue}└{'─' * (max_ssid_width + 2)}┴{'─' * (max_bssid_width + 2)}"
            f"┴{'─' * (max_signal_width + 2)}┴{'─' * (max_ch_width + 2)}"
            f"┴{'─' * (max_bcn_width + 2)}┴{'─' * (max_data_width + 2)}"
            f"┴{'─' * (status_width + 2)}┴{'─' * (quality_width + 2)}┘{reset}"
        )
        
        output.append(bottom_line)

        # After the main table's bottom line, add a colored section for jammed networks
        if self.attackers:
            jammed_networks = [
                (bssid, data) for bssid, data in self.networks.items() 
                if data['suspicious_activity'] > 5
            ]
            
            if jammed_networks:
                # Define colors for better visibility
                alert_bg = "\033[41m"    # Red background
                alert_fg = "\033[97m"    # Bright white text
                border_color = "\033[31m" # Red for borders
                
                # Warning header with background
                output.append(f"\n{alert_bg}{alert_fg} ⚠ JAMMED NETWORKS DETECTED ⚠ {reset}")
                
                # Table header with colored borders
                output.append(
                    f"{border_color}┌{'─' * 14}┬{'─' * 19}┬{'─' * 12}┐{reset}"
                )
                
                # Column headers with background color
                output.append(
                    f"{border_color}│{alert_bg}{alert_fg} {'SSID'.ljust(12)} "
                    f"{border_color}│{alert_bg}{alert_fg} {'BSSID'.ljust(17)} "
                    f"{border_color}│{alert_bg}{alert_fg} {'Duration'.ljust(10)} "
                    f"{border_color}│{reset}"
                )
                
                # Separator line
                output.append(
                    f"{border_color}├{'─' * 14}┼{'─' * 19}┼{'─' * 12}┤{reset}"
                )
                
                # List jammed networks with background color
                current_time = time.time()
                for bssid, data in jammed_networks:
                    duration = int(current_time - data['first_seen'])
                    ssid = data['ssid'][:12].ljust(12)
                    duration_str = f"{duration}s".ljust(10)
                    
                    output.append(
                        f"{border_color}│{alert_bg}{alert_fg} {ssid} "
                        f"{border_color}│{alert_bg}{alert_fg} {bssid.ljust(17)} "
                        f"{border_color}│{alert_bg}{alert_fg} {duration_str} "
                        f"{border_color}│{reset}"
                    )
                
                # Bottom border
                output.append(
                    f"{border_color}└{'─' * 14}┴{'─' * 19}┴{'─' * 12}┘{reset}"
                )
                
                # Warning message with background
                output.append(f"{alert_bg}{alert_fg} ! Warning: These networks may be under active attack {reset}")

        # Statistics line
        elapsed = time.time() - list(self.networks.values())[0]['first_seen'] if self.networks else 0
        output.append(f"\n{yellow}Elapsed: {white}{int(elapsed)}s {yellow}| Networks: {white}{len(self.networks)} "
                     f"{yellow}| {green}Normal: {len(self.networks) - len(self.attackers)} "
                     f"{yellow}| {red}Jammed: {len(self.attackers)}{reset}")

        # Print all at once
        print('\n'.join(output))

    def start_monitoring(self):
        self.is_monitoring = True
        
        try:
            # Start channel hopping in a separate thread
            channel_hopper = threading.Thread(target=self.channel_hopper)
            channel_hopper.daemon = True
            channel_hopper.start()

            # Initial screen setup
            os.system('clear')
            print("\033[?25l")  # Hide cursor
            
            while self.is_monitoring:
                # Continuous scanning
                sniff(iface=self.interface, prn=self.packet_handler, timeout=0.1)
                
                # Update display without clearing screen
                current_time = time.time()
                if current_time - self.last_update_time >= 0.5:  # Update every 0.5 seconds
                    self.update_display()
                    self.last_update_time = current_time
                    self.clean_old_networks()
                
                time.sleep(0.1)
                
        except Exception as e:
            print(f"{red}[!] Error: {str(e)}{reset}")
        finally:
            print("\033[?25h")  # Show cursor on exit

    def update_display(self):
        """Update display without screen clearing"""
        # Move cursor to home position
        print("\033[H", end='')
        
        # Generate the display content
        self.print_status()

    def channel_hopper(self):
        """Hop through channels 1-14"""
        while self.is_monitoring:
            for channel in range(1, 15):
                try:
                    subprocess.run(['iwconfig', self.interface, 'channel', str(channel)], 
                                 stdout=subprocess.DEVNULL, 
                                 stderr=subprocess.DEVNULL)
                    self.channel = channel
                    time.sleep(0.1)  # Spend 0.1 seconds on each channel
                except:
                    continue

    def clean_old_networks(self):
        """Remove networks not seen in last 30 seconds"""
        current_time = time.time()
        networks_to_remove = []
        
        for bssid, data in self.networks.items():
            if current_time - data['last_seen'] > 30:
                networks_to_remove.append(bssid)
        
        for bssid in networks_to_remove:
            del self.networks[bssid]

    def start(self):
        self.check_root()
        if self.setup_monitor_mode():
            try:
                self.start_monitoring()
            except KeyboardInterrupt:
                print("\n\033[1;33m[*] Shutting down EchoProbe...\033[0m")
                self.cleanup()

if __name__ == "__main__":
    probe = EchoProbe()
    probe.start()