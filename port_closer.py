import os
import platform
import subprocess
import time

SAFE_MODE = True

def detect_os():
    return platform.system()

def get_process_name(pid):
    os_type = detect_os()
    try:
        if os_type == "Linux":
            cmd = f"ps -p {pid} -o comm="
            return subprocess.check_output(cmd, shell=True, text=True).strip()
        elif os_type == "Windows":
            cmd = f'tasklist /FI "PID eq {pid}"'
            output = subprocess.check_output(cmd, shell=True, text=True)
            lines = output.strip().splitlines()
            if len(lines) >= 4:
                return lines[3].split()[0]
        return "Unknown"
    except:
        return "Unknown"

def confirm_action(prompt):
    if SAFE_MODE:
        choice = input(f"{prompt} (y/N): ").strip().lower()
        return choice == 'y'
    return True

def get_open_ports():
    os_type = detect_os()
    ports = []
    seen = set()
    try:
        if os_type == "Linux":
            tcp_cmd = "sudo lsof -nP -iTCP -sTCP:LISTEN"
            udp_cmd = "sudo lsof -nP -iUDP"
            output_tcp = subprocess.check_output(tcp_cmd, shell=True, text=True)
            output_udp = subprocess.check_output(udp_cmd, shell=True, text=True)
            lines = output_tcp.strip().split('\n')[1:] + output_udp.strip().split('\n')[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 9:
                    pid = parts[1]
                    name = parts[0]
                    proto = "UDP" if "UDP" in parts[7] else "TCP"
                    port_info = parts[8].split(":")[-1]
                    if (port_info, pid, proto) not in seen:
                        ports.append((port_info, pid, name, proto))
                        seen.add((port_info, pid, proto))
        elif os_type == "Windows":
            netstat_cmd = "netstat -ano"
            netstat_output = subprocess.check_output(netstat_cmd, shell=True, text=True).splitlines()
            for line in netstat_output:
                if "LISTENING" in line or "UDP" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0]
                        local_addr = parts[1]
                        pid = parts[-1]
                        port = local_addr.split(":")[-1]
                        name = get_process_name(pid)
                        if (port, pid, proto) not in seen:
                            ports.append((port, pid, name, proto))
                            seen.add((port, pid, proto))
    except Exception as e:
        print(f"[!] Failed to detect open ports: {e}")
    return ports

def get_established_connections():
    os_type = detect_os()
    connections = []
    try:
        if os_type == "Linux":
            cmd = "netstat -ntp"
            output = subprocess.check_output(cmd, shell=True, text=True).splitlines()
            for line in output:
                if "ESTABLISHED" in line:
                    parts = line.split()
                    proto = parts[0]
                    local_full = parts[3]
                    remote_full = parts[4]
                    pid_program = parts[6] if len(parts) >= 7 else "-"
                    pid = pid_program.split("/")[0] if "/" in pid_program else "-"
                    proc_name = get_process_name(pid) if pid != "-" else "-"
                    local_ip, local_port = local_full.rsplit(":", 1)
                    remote_ip, remote_port = remote_full.rsplit(":", 1)
                    connections.append((proto, local_ip, local_port, remote_ip, remote_port, pid, proc_name))
        elif os_type == "Windows":
            cmd = "netstat -ano"
            output = subprocess.check_output(cmd, shell=True, text=True).splitlines()
            for line in output:
                if "ESTABLISHED" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0]
                        local_full = parts[1]
                        remote_full = parts[2]
                        pid = parts[4]
                        proc_name = get_process_name(pid)
                        local_ip, local_port = local_full.rsplit(":", 1)
                        remote_ip, remote_port = remote_full.rsplit(":", 1)
                        connections.append((proto, local_ip, local_port, remote_ip, remote_port, pid, proc_name))
    except Exception as e:
        print(f"[!] Failed to get established connections: {e}")
    return connections

def display_ports(ports):
    print("\n📡 Detected Open Ports:")
    for i, (port, pid, name, proto) in enumerate(ports):
        print(f"  [{i}] {proto} Port: {port} | PID: {pid} | Process: {name}")

def display_connections(connections):
    print("\n🔗 Established Connections:")
    for i, (proto, local_ip, local_port, remote_ip, remote_port, pid, proc_name) in enumerate(connections):
        print(f"  [{i}] {proto} | Local: {local_ip}:{local_port} | Remote: {remote_ip}:{remote_port} | PID: {pid} | Process: {proc_name}")

def kill_process(pid):
    os_type = detect_os()
    if not confirm_action(f"[SAFE MODE] Confirm killing process {pid}?"):
        print("[*] Action canceled.")
        return
    try:
        if os_type == "Linux":
            subprocess.run(f"sudo kill -9 {pid}", shell=True, check=True)
        elif os_type == "Windows":
            subprocess.run(f"taskkill /PID {pid} /F", shell=True, check=True)
        print(f"[+] Process {pid} terminated.")
    except Exception as e:
        print(f"[!] Failed to kill process {pid}: {e}")

def block_port(port, proto):
    os_type = detect_os()
    if not confirm_action(f"[SAFE MODE] Confirm blocking port {port}/{proto}?"):
        print("[*] Action canceled.")
        return
    try:
        if os_type == "Linux":
            subprocess.run(f"sudo ufw deny {proto.lower()}/{port}", shell=True, check=True)
        elif os_type == "Windows":
            subprocess.run(f'netsh advfirewall firewall add rule name="BlockPort{port}" dir=in action=block protocol={proto} localport={port}', shell=True, check=True)
        print(f"[+] Port {port}/{proto} blocked.")
    except Exception as e:
        print(f"[!] Failed to block port {port}: {e}")

def close_port_by_number():
    port = input("Enter port number to close: ").strip()
    if not port.isdigit():
        print("[!] Invalid port.")
        return
    proto = input("Protocol? [TCP/UDP]: ").strip().upper()
    if proto not in ('TCP', 'UDP'):
        print("[!] Invalid protocol.")
        return
    ports = get_open_ports()
    found = False
    for port_num, pid, proc_name, proto_in_list in ports:
        if port_num == port and proto_in_list.upper() == proto:
            found = True
            print(f"Found: PID {pid}, Process {proc_name}")
            action = input("Action:\n  [1] Kill process\n  [2] Kill+Block\n  [3] Skip\nYour choice: ").strip()
            if action == '1':
                kill_process(pid)
            elif action == '2':
                kill_process(pid)
                block_port(port, proto)
            elif action == '3':
                print("[*] Skipped.")
            else:
                print("[!] Invalid choice.")
    if not found:
        print("[!] No process found listening on that port.")

def main():
    global SAFE_MODE
    while True:
        print("\nMode options:\n"
              "  [1] Manual port control\n"
              "  [2] Auto-monitor mode\n"
              "  [3] Scan now, then launch auto-monitor\n"
              f"  [4] Toggle Safe Mode (currently: {'ON' if SAFE_MODE else 'OFF'})\n"
              "  [5] View established connections\n"
              "  [6] Close port by entering port number\n"
              "  [q] Quit")
        mode = input("Choose a mode: ").strip()
        if mode == '1':
            ports = get_open_ports()
            if not ports:
                print("No open TCP/UDP ports found.")
                continue
            display_ports(ports)
            while True:
                choice = input("\nSelect index to manage (or 'b' to go back): ").strip()
                if choice.lower() == 'b':
                    break
                if not choice.isdigit() or int(choice) >= len(ports):
                    print("[!] Invalid selection.")
                    continue
                port, pid, name, proto = ports[int(choice)]
                action = input(f"\nFor {proto} port {port} (PID {pid}, Process {name}), choose:\n"
                               "  [1] Kill process\n  [2] Kill+Block\n  [3] Skip\nYour choice: ").strip()
                if action == '1':
                    kill_process(pid)
                elif action == '2':
                    kill_process(pid)
                    block_port(port, proto)
                elif action == '3':
                    print("[*] Skipped.")
                else:
                    print("[!] Invalid choice.")
        elif mode == '2':
            delay = input("Scan interval seconds [default 10]: ").strip()
            delay = int(delay) if delay.isdigit() else 10
            auto_monitor(delay)
        elif mode == '3':
            ports = get_open_ports()
            display_ports(ports)
            input("\nPress Enter to start auto-monitor...")
            delay = input("Scan interval seconds [default 10]: ").strip()
            delay = int(delay) if delay.isdigit() else 10
            auto_monitor(delay)
        elif mode == '4':
            SAFE_MODE = not SAFE_MODE
            print(f"[~] Safe Mode is now {'ON' if SAFE_MODE else 'OFF'}")
        elif mode == '5':
            connections = get_established_connections()
            if not connections:
                print("No established connections found.")
                continue
            display_connections(connections)
            input("\nPress Enter to go back.")
        elif mode == '6':
            close_port_by_number()
        elif mode.lower() == 'q':
            print("Goodbye!")
            break
        else:
            print("[!] Invalid option.")

def auto_monitor(delay=10):
    print(f"\n[~] Auto-monitoring every {delay} seconds. Press Ctrl+C to stop.")
    known_ports = set()
    try:
        while True:
            current = get_open_ports()
            current_set = set((p[0], p[1], p[3]) for p in current)
            new_ports = [p for p in current if (p[0], p[1], p[3]) not in known_ports]
            for port, pid, name, proto in new_ports:
                print(f"\n[⚠️] New {proto} port: {port} | PID: {pid} | Process: {name}")
                action = input("  [1] Kill [2] Kill+Block [Enter] Ignore: ").strip()
                if action == '1':
                    kill_process(pid)
                elif action == '2':
                    kill_process(pid)
                    block_port(port, proto)
                else:
                    print("[*] Ignored.")
            known_ports = current_set
            time.sleep(delay)
    except KeyboardInterrupt:
        print("\n[!] Auto-monitor stopped.")

if __name__ == "__main__":
    main()
