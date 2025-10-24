#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <unistd.h>

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;

static uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

static string mac_to_str(const uint8_t mac[6]) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(buf);
}

static string ipv4_to_str(const uint8_t *p) {
    char b[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, p, b, sizeof(b));
    return string(b);
}

static string ipv6_to_str(const uint8_t *p) {
    char b[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, p, b, sizeof(b));
    return string(b);
}

template<typename T>
class CustomStack {
private:
    vector<T> data_;
public:
    CustomStack() {}
    void push(const T &v) { data_.push_back(v); }
    T pop() {
        if (data_.empty()) throw runtime_error("Stack underflow");
        T v = data_.back();
        data_.pop_back();
        return v;
    }
    T &top() {
        if (data_.empty()) throw runtime_error("Stack empty");
        return data_.back();
    }
    bool empty() const { return data_.empty(); }
    size_t size() const { return data_.size(); }
    void clear() { data_.clear(); }
};

template<typename T>
class CustomQueue {
private:
    struct Node {
        T val;
        Node *next;
        Node(const T &v) : val(v), next(nullptr) {}
    };
    Node *head;
    Node *tail;
    size_t count;
public:
    CustomQueue() : head(nullptr), tail(nullptr), count(0) {}
    ~CustomQueue() {
        while (head) {
            Node *n = head;
            head = head->next;
            delete n;
        }
    }
    void push(const T &v) {
        Node *n = new Node(v);
        if (!tail) head = tail = n;
        else { tail->next = n; tail = n; }
        ++count;
    }
    bool pop(T &out) {
        if (!head) return false;
        Node *n = head;
        out = n->val;
        head = head->next;
        if (!head) tail = nullptr;
        delete n;
        --count;
        return true;
    }
    bool peek(T &out) const {
        if (!head) return false;
        out = head->val;
        return true;
    }
    size_t size() const { return count; }
    bool empty() const { return count == 0; }

    vector<T> snapshot() const {
        vector<T> out;
        Node *cur = head;
        while (cur) { out.push_back(cur->val); cur = cur->next; }
        return out;
    }
};

struct Packet {
    uint64_t id;
    uint64_t timestamp_ms; 
    vector<uint8_t> buf;  
    string src_ip;
    string dst_ip;
    size_t retries;        
    size_t orig_size;       
    Packet() : id(0), timestamp_ms(0), retries(0), orig_size(0) {}
};

enum LayerType { LAYER_ETH, LAYER_IPV4, LAYER_IPV6, LAYER_TCP, LAYER_UDP, LAYER_UNKNOWN };

struct DissectedLayers {
    vector<pair<LayerType, string>> layers; 
};

class Dissector {
public:

    static DissectedLayers dissect(const vector<uint8_t> &buf, Packet &pkt) {
        DissectedLayers result;
        CustomStack<pair<LayerType, size_t>> stack; // layer type and offset
        if (buf.size() < sizeof(ether_header)) {
            result.layers.push_back({LAYER_UNKNOWN, "Frame too short"});
            return result;
        }

        stack.push({LAYER_ETH, 0});
        while (!stack.empty()) {
            auto item = stack.pop();
            LayerType layer = item.first;
            size_t offset = item.second;
            if (layer == LAYER_ETH) {
                if (offset + sizeof(ether_header) > buf.size()) {
                    result.layers.push_back({LAYER_ETH, "truncated ethernet header"});
                    break;
                }
                const ether_header *eth = reinterpret_cast<const ether_header*>(buf.data() + offset);
                uint16_t eth_type = ntohs(eth->ether_type);
                string s = "src=" + mac_to_str(eth->ether_shost) + " dst=" + mac_to_str(eth->ether_dhost)
                           + " type=0x" + hex_str(eth_type);
                result.layers.push_back({LAYER_ETH, s});
                size_t next_offset = offset + sizeof(ether_header);
                if (eth_type == ETH_P_IP) {
                    stack.push({LAYER_IPV4, next_offset});
                } else if (eth_type == ETH_P_IPV6) {
                    stack.push({LAYER_IPV6, next_offset});
                } else {
                }
            } else if (layer == LAYER_IPV4) {
                if (offset + sizeof(iphdr) > buf.size()) {
                    result.layers.push_back({LAYER_IPV4, "truncated ip header"});
                    break;
                }
                const iphdr *ip = reinterpret_cast<const iphdr*>(buf.data() + offset);
                size_t ihl_bytes = ip->ihl * 4;
                if (offset + ihl_bytes > buf.size()) {
                    result.layers.push_back({LAYER_IPV4, "truncated ip header (ihl)"});
                    break;
                }
                uint8_t proto = ip->protocol;
                uint8_t src[4], dst[4];
                memcpy(src, &ip->saddr, 4);
                memcpy(dst, &ip->daddr, 4);
                string srcs = ipv4_to_str((uint8_t*)&ip->saddr);
                string dsts = ipv4_to_str((uint8_t*)&ip->daddr);
              
                if (pkt.src_ip.empty()) pkt.src_ip = srcs;
                if (pkt.dst_ip.empty()) pkt.dst_ip = dsts;
                string s = "v=4 src=" + srcs + " dst=" + dsts + " proto=" + to_string(proto);
                result.layers.push_back({LAYER_IPV4, s});
                size_t next_offset = offset + ihl_bytes;
                if (proto == IPPROTO_TCP) stack.push({LAYER_TCP, next_offset});
                else if (proto == IPPROTO_UDP) stack.push({LAYER_UDP, next_offset});
            } else if (layer == LAYER_IPV6) {
                if (offset + sizeof(ip6_hdr) > buf.size()) {
                    result.layers.push_back({LAYER_IPV6, "truncated ipv6 header"});
                    break;
                }
                const ip6_hdr *ip6 = reinterpret_cast<const ip6_hdr*>(buf.data() + offset);
                uint8_t nxt = ip6->ip6_nxt;
        
                char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
                inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));
                string srcs = string(src);
                string dsts = string(dst);
                if (pkt.src_ip.empty()) pkt.src_ip = srcs;
                if (pkt.dst_ip.empty()) pkt.dst_ip = dsts;
                string s = "v=6 src=" + srcs + " dst=" + dsts + " nxt=" + to_string(nxt);
                result.layers.push_back({LAYER_IPV6, s});
                size_t next_offset = offset + sizeof(ip6_hdr);
                if (nxt == IPPROTO_TCP) stack.push({LAYER_TCP, next_offset});
                else if (nxt == IPPROTO_UDP) stack.push({LAYER_UDP, next_offset});
            } else if (layer == LAYER_TCP) {
                if (offset + sizeof(tcphdr) > buf.size()) {
                    result.layers.push_back({LAYER_TCP, "truncated tcp header"});
                    break;
                }
                const tcphdr *tcp = reinterpret_cast<const tcphdr*>(buf.data() + offset);
                uint16_t sport = ntohs(tcp->source);
                uint16_t dport = ntohs(tcp->dest);
                string s = "TCP srcport=" + to_string(sport) + " dstport=" + to_string(dport);
                result.layers.push_back({LAYER_TCP, s});
              
            } else if (layer == LAYER_UDP) {
                if (offset + sizeof(udphdr) > buf.size()) {
                    result.layers.push_back({LAYER_UDP, "truncated udp header"});
                    break;
                }
                const udphdr *udp = reinterpret_cast<const udphdr*>(buf.data() + offset);
                uint16_t sport = ntohs(udp->source);
                uint16_t dport = ntohs(udp->dest);
                string s = "UDP srcport=" + to_string(sport) + " dstport=" + to_string(dport);
                result.layers.push_back({LAYER_UDP, s});
            } else {
                result.layers.push_back({LAYER_UNKNOWN, "unknown layer"});
            }
        }
        return result;
    }
private:
    static string hex_str(uint16_t v) {
        char b[8];
        snprintf(b, sizeof(b), "%04x", v);
        return string(b);
    }
};

class NetworkMonitor {
private:
    string iface;
    int sock_fd;              
    int send_sock_fd;         
    atomic<bool> running;
    atomic<uint64_t> packet_counter;

    // Queues and lists
    CustomQueue<shared_ptr<Packet>> capture_queue;   // captured packets to process
    CustomQueue<shared_ptr<Packet>> replay_queue;    // filtered packets waiting to replay
    CustomQueue<shared_ptr<Packet>> backup_queue;    // packets moved here on failure

    // For demonstration & statistics
    mutex display_mutex; // guards console output for pretty printing
    mutex capq_mutex;    // guard for capture_queue operations when needed
    mutex replayq_mutex;
    mutex backupq_mutex;

    // Limits & thresholds
    const size_t MAX_PACKET_SIZE = 65535;
    const size_t MTU_THRESHOLD = 1500; // skip oversized packets under some condition
    const size_t OVERSIZE_SKIP_COUNT_THRESHOLD = 50;

    // Oversize counter
    atomic<size_t> oversize_count;

    // Filtering criteria (simple ip strings)
    string filter_src;
    string filter_dst;

    // interface hardware info
    int ifindex;
    uint8_t if_mac[6];

public:
    NetworkMonitor(const string &interface_name, const string &fsrc, const string &fdst)
        : iface(interface_name), sock_fd(-1), send_sock_fd(-1),
          running(false), packet_counter(1), oversize_count(0),
          filter_src(fsrc), filter_dst(fdst), ifindex(0) {
        memset(if_mac, 0, sizeof(if_mac));
    }

    ~NetworkMonitor() {
        stop();
    }

    // Initialize sockets & interface
    bool init() {
        // Open raw socket for capture
        sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock_fd < 0) {
            perror("socket(AF_PACKET) capture");
            return false;
        }

        // Get interface index and MAC
        ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
        if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) == -1) {
            perror("ioctl SIOCGIFINDEX");
            close(sock_fd);
            sock_fd = -1;
            return false;
        }
        ifindex = ifr.ifr_ifindex;

        if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) == -1) {
            perror("ioctl SIOCGIFHWADDR");
            // non-fatal
        } else {
            memcpy(if_mac, ifr.ifr_hwaddr.sa_data, 6);
        }

        // Bind socket to interface
        sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(sock_fd, (sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("bind capture socket");
            close(sock_fd);
            sock_fd = -1;
            return false;
        }

        // Socket for sending (replay)
        send_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (send_sock_fd < 0) {
            perror("socket(AF_PACKET) send");
            // We still can proceed (but replay will likely fail)
        } else {
            // no bind required; we will set sockaddr_ll in sendto
        }

        return true;
    }

    void start() {
        if (running) return;
        running = true;
        // spawn threads
        threads.emplace_back(&NetworkMonitor::capture_loop, this);
        threads.emplace_back(&NetworkMonitor::process_loop, this);
        threads.emplace_back(&NetworkMonitor::replay_loop, this);
    }

    void stop() {
        if (!running) return;
        running = false;
        // close sockets to unblock recv
        if (sock_fd >= 0) close(sock_fd);
        if (send_sock_fd >= 0) close(send_sock_fd);
        // join threads
        for (auto &t : threads) {
            if (t.joinable()) t.join();
        }
        threads.clear();
    }

    // Display functions
    void display_packet_list() {
        lock_guard<mutex> lock(display_mutex);
        cout << "\n=== Current Packet List (capture queue) ===\n";
        auto snap = capture_queue.snapshot();
        cout << "Total captured in queue: " << snap.size() << "\n";
        cout << left << setw(6) << "ID" << setw(16) << "Timestamp(ms)" << setw(20) << "Src IP" << setw(20) << "Dst IP" << setw(8) << "Size" << "\n";
        for (const auto &p_ptr : snap) {
            cout << setw(6) << p_ptr->id << setw(16) << p_ptr->timestamp_ms << setw(20) << (p_ptr->src_ip.empty() ? "-" : p_ptr->src_ip)
                 << setw(20) << (p_ptr->dst_ip.empty() ? "-" : p_ptr->dst_ip) << setw(8) << p_ptr->orig_size << "\n";
        }
    }

    void display_dissection(const shared_ptr<Packet> &p) {
        lock_guard<mutex> lock(display_mutex);
        cout << "\n=== Dissected layers for packet ID " << p->id << " ===\n";
        auto layers = Dissector::dissect(p->buf, *p);
        for (auto &entry : layers.layers) {
            string layername = layer_to_str(entry.first);
            cout << layername << ": " << entry.second << "\n";
        }
    }

    void display_filtered_packets_with_delay() {
        lock_guard<mutex> lock(display_mutex);
        cout << "\n=== Filtered / Replay Queue ===\n";
        auto snap = replay_queue.snapshot();
        cout << left << setw(6) << "ID" << setw(16) << "Timestamp" << setw(20) << "Src" << setw(20) << "Dst" << setw(10) << "Delay(ms)" << "\n";
        for (const auto &p_ptr : snap) {
            size_t delay = estimate_delay_ms(p_ptr->orig_size);
            cout << setw(6) << p_ptr->id << setw(16) << p_ptr->timestamp_ms << setw(20) << p_ptr->src_ip << setw(20) << p_ptr->dst_ip << setw(10) << delay << "\n";
        }
    }

    // Demo-run helper - wait for X seconds while capturing/processing
    void demo_run_for_seconds(int seconds) {
        cout << "Starting demo run for " << seconds << " seconds. Capturing on interface '" << iface << "'\n";
        start();
        this_thread::sleep_for(chrono::seconds(seconds));
        cout << "Stopping capture & processing ...\n";
        stop();

        // After stopping, display stats and lists
        display_packet_list();
        display_filtered_packets_with_delay();

        // show backup contents
        auto backup_snap = backup_queue.snapshot();
        if (!backup_snap.empty()) {
            cout << "\n=== Backup queue (failed replays) ===\n";
            for (auto &p : backup_snap) {
                cout << "ID " << p->id << " size=" << p->orig_size << " retries=" << p->retries << "\n";
            }
        } else {
            cout << "\nNo packets in backup queue.\n";
        }
    }

private:
    vector<thread> threads;

    // Capture loop: read from raw socket and push to capture_queue
    void capture_loop() {
        cout << "[capture_loop] started\n";
        // Buffer
        vector<uint8_t> buffer(MAX_PACKET_SIZE);
        while (running) {
            ssize_t r = recv(sock_fd, buffer.data(), buffer.size(), 0);
            if (r < 0) {
                if (!running) break;
                if (errno == EINTR) continue;
                perror("[capture_loop] recv");
                // small sleep to avoid tight loop on persistent error
                this_thread::sleep_for(chrono::milliseconds(100));
                continue;
            }
            // Copy packet into vector
            auto p = make_shared<Packet>();
            p->id = packet_counter.fetch_add(1);
            p->timestamp_ms = now_ms();
            p->orig_size = static_cast<size_t>(r);
            p->buf.assign(buffer.data(), buffer.data() + r);

            // Early oversize handling
            if (p->orig_size > MTU_THRESHOLD) {
                size_t cur = oversize_count.fetch_add(1) + 1;
                if (cur > OVERSIZE_SKIP_COUNT_THRESHOLD) {
                    // Skip (drop) this packet
                    continue;
                }
            }

            // Push into capture queue
            {
                // push directly (CustomQueue is thread-safe enough for single-producer single-consumer in this usage)
                capture_queue.push(p);
            }
        }
        cout << "[capture_loop] exiting\n";
    }

    // Process loop: take from capture_queue, dissect, filter -> move to replay queue if matches
    void process_loop() {
        cout << "[process_loop] started\n";
        while (running || !capture_queue.empty()) {
            shared_ptr<Packet> p;
            bool got = capture_queue.pop(p);
            if (!got) {
                // sleep briefly and continue
                this_thread::sleep_for(chrono::milliseconds(50));
                continue;
            }
            // Dissect using Dissector; this also fills src/dst in packet
            auto layers = Dissector::dissect(p->buf, *p);
            // For demo, print dissect for first few packets
            {
                lock_guard<mutex> lock(display_mutex);
                if (p->id % 50 == 0) {
                    cout << "[process_loop] dissecting packet id=" << p->id << " size=" << p->orig_size << "\n";
                }
            }
            // Filter based on src/dst if provided
            bool matches = matches_filter(p);
            if (matches) {
                // push into replay queue
                replay_queue.push(p);
            }
            // continue processing
        }
        cout << "[process_loop] exiting\n";
    }

    // Replay loop: continuously pick from replay_queue and attempt to send
    void replay_loop() {
        cout << "[replay_loop] started\n";
        while (running || !replay_queue.empty()) {
            shared_ptr<Packet> p;
            bool got = replay_queue.pop(p);
            if (!got) {
                this_thread::sleep_for(chrono::milliseconds(50));
                continue;
            }
            // Estimate delay and sleep
            size_t delay_ms = estimate_delay_ms(p->orig_size);
            if (delay_ms > 0) this_thread::sleep_for(chrono::milliseconds(delay_ms));

            bool sent = try_replay_packet(p);
            if (!sent) {
                // add to backup and maybe retry
                p->retries++;
                if (p->retries <= 2) {
                    // retry by pushing back to replay queue (simple policy)
                    replay_queue.push(p);
                } else {
                    backup_queue.push(p);
                }
            } else {
                // success - nothing to do
            }
        }
        cout << "[replay_loop] exiting\n";
    }

    // Try to send packet via raw socket; return true if success
    bool try_replay_packet(const shared_ptr<Packet> &p) {
        if (send_sock_fd < 0) {
            // cannot send
            return false;
        }
        // Prepare sockaddr_ll with interface index and dest MAC from frame
        if (p->buf.size() < sizeof(ether_header)) return false;
        const ether_header *eth = reinterpret_cast<const ether_header*>(p->buf.data());
        sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_halen = ETH_ALEN;
        memcpy(sll.sll_addr, eth->ether_dhost, 6);
        // send
        ssize_t sent = sendto(send_sock_fd, p->buf.data(), p->buf.size(), 0, (sockaddr*)&sll, sizeof(sll));
        if (sent == (ssize_t)p->buf.size()) {
            lock_guard<mutex> lock(display_mutex);
            cout << "[replay] packet id=" << p->id << " replayed size=" << p->orig_size << "\n";
            return true;
        } else {
            lock_guard<mutex> lock(display_mutex);
            cerr << "[replay] failed to replay id=" << p->id << " sent=" << sent << " errno=" << errno << " (" << strerror(errno) << ")\n";
            return false;
        }
    }

    size_t estimate_delay_ms(size_t packet_size) const {

        return packet_size / 1000;
    }

    // Does packet match filtering criteria
    bool matches_filter(const shared_ptr<Packet> &p) const {
        // If both filter_src and filter_dst empty -> accept all
        if (filter_src.empty() && filter_dst.empty()) return true;
        if (!filter_src.empty() && p->src_ip.find(filter_src) == string::npos) return false;
        if (!filter_dst.empty() && p->dst_ip.find(filter_dst) == string::npos) return false;
        return true;
    }

    static string layer_to_str(LayerType l) {
        switch (l) {
            case LAYER_ETH: return "Ethernet";
            case LAYER_IPV4: return "IPv4";
            case LAYER_IPV6: return "IPv6";
            case LAYER_TCP: return "TCP";
            case LAYER_UDP: return "UDP";
            default: return "Unknown";
        }
    }
};


int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        cerr << "Warning: this program is best run as root for raw socket capture & replay.\n";
    }
    if (argc < 2) {
        cerr << "Usage: sudo ./network_monitor <interface> [filter_src_ip] [filter_dst_ip]\n";
        cerr << "Example: sudo ./network_monitor eth0 192.168.1.10 192.168.1.20\n";
        return 1;
    }
    string iface = argv[1];
    string fsrc = "";
    string fdst = "";
    if (argc >= 3) fsrc = argv[2];
    if (argc >= 4) fdst = argv[3];

    cout << "Network Monitor starting on interface: " << iface << "\n";
    cout << "Filter src: " << (fsrc.empty() ? "<any>" : fsrc) << " dst: " << (fdst.empty() ? "<any>" : fdst) << "\n";

    NetworkMonitor nm(iface, fsrc, fdst);
    if (!nm.init()) {
        cerr << "Initialization failed. Are you root? Does the interface exist?\n";
        return 1;
    }

    nm.demo_run_for_seconds(60);

    cout << "Demo complete. Exiting.\n";
    return 0;
}