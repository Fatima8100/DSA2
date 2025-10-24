 Network Monitor Assignment 2

 About the Project

This project is a simple **Network Packet Monitor** built in **C++**, created as part of my Data Structures & Algorithms course.  
The main goal was to take something real-world (like packet sniffing) and implement it using **custom data structures** — specifically, a **stack** and a **queue** instead of relying on STL versions.

It continuously captures network packets from a given interface, breaks them down layer by layer (Ethernet, IP, TCP/UDP), filters based on IPs, and even replays some of them with a delay and retry system.

Think of it as a tiny, homemade version of Wireshark — but coded from scratch for learning.

 What It Can Do

- Capture packets from your network interface using raw sockets  
- Dissect packets layer by layer using a custom **stack**  
- Store and manage packets using a custom **queue**  
- Filter traffic between specific IP addresses  
- Replay filtered packets with a simple delay formula  
- Retry replay twice if a send fails  
- Skip oversized packets once the threshold is reached  
- Display packet info (IDs, IPs, timestamps, etc.)

Requirements

Requirement | Description 

OS          | Linux (Ubuntu recommended) 
Privileges  | Root (for raw sockets) 
Compiler    | g++ (C++17 or newer) 
Interface   | Example: `eth0`, `wlan0`, `enp3s0` 


How to Build

1. Open the folder in **VS Code** or a Linux terminal.  
2. Compile using:
   bash
   g++ -std=c++17 -pthread -O2 network_monitor.cpp -o network_monitor
   
How to Run

Because it uses raw sockets, you need to run it as root:

bash
sudo ./network_monitor <interface>


Example:
bash
sudo ./network_monitor wlan0


You can also filter packets by source and destination IPs:
bash
sudo ./network_monitor wlan0 192.168.1.10 192.168.1.20



Sample Output

Network Monitor starting on interface: wlan0
Filter src: 192.168.1.10 dst: 192.168.1.20
Starting demo run for 60 seconds...
[capture_loop] started
[process_loop] started
[replay_loop] started

=== Current Packet List ===
ID    Timestamp(ms)   Src IP             Dst IP             Size
1     123456789       192.168.1.10       192.168.1.20       98

Demo complete. Exiting.



Behind the Scenes

Here’s how it works internally:
1. **Capture:** Raw socket listens for packets on your chosen interface.  
2. **Dissection:** Stack-based parsing identifies Ethernet, IP, and TCP/UDP layers.  
3. **Filtering:** Queue holds only packets that match the given IP filters.  
4. **Replay:** Those packets are sent again with calculated delay (`packet_size / 1000 ms`).  
5. **Error Handling:** If replay fails, it retries up to 2 times, then moves the packet to a backup queue.  


How to Test It

You can open two terminals:
- One runs your program  
- The other pings or browses something to generate traffic  

Example:
bash
ping google.com


Then check your program’s output, it should start showing packets being captured and processed.


What I Learned

- How **stacks** and **queues** can structure real-time systems  
- Basics of **raw socket programming** in Linux  
- How to dissect packet layers manually (Ethernet → IP → TCP/UDP)  
- Threading and synchronization for live data  
- Handling failures and retries systematically  

 Notes

- Always run with `sudo` (raw sockets won’t work otherwise)  
- If no packets show up, try a more active interface or generate some traffic  
- Some systems block raw packet replay — that’s expected  
- You can stop the program early using `Ctrl + C`  


Made by 

Fatima Ahmed


