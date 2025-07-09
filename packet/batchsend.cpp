#include <iostream>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

class PacketBatchSender {
private:
    struct PacketInfo {
        const void* data;
        size_t size;
        sockaddr* remote;
        int addrlen;
    };

    int socket_fd_;
    struct tpacket_req req_;
    char* ring_buffer_;
    size_t ring_buffer_size_;
    std::vector<PacketInfo> packet_queue_;
    unsigned int current_frame_;
    struct ifreq ifr_;
    int ifindex_;

public:
    PacketBatchSender(const char* interface_name, int ring_frames = 128, size_t frame_size = 2048) {
        // 创建 AF_PACKET 套接字
        socket_fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        if (socket_fd_ < 0) {
            throw std::runtime_error("Failed to create AF_PACKET socket");
        }

        // 获取网络接口索引
        memset(&ifr_, 0, sizeof(ifr_));
        strncpy(ifr_.ifr_name, interface_name, IFNAMSIZ - 1);
        if (ioctl(socket_fd_, SIOCGIFINDEX, &ifr_) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to get interface index");
        }
        ifindex_ = ifr_.ifr_ifindex;

        // 绑定套接字到指定网络接口
        struct sockaddr_ll addr;
        memset(&addr, 0, sizeof(addr));
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_IP);
        addr.sll_ifindex = ifindex_;
        if (bind(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to bind to interface");
        }

        // 设置 TX_RING 参数
        memset(&req_, 0, sizeof(req_));
        req_.tp_block_size = getpagesize(); // 默认页大小
        req_.tp_block_nr = ring_frames * frame_size / req_.tp_block_size;
        if (req_.tp_block_nr == 0) req_.tp_block_nr = 1;
        req_.tp_frame_size = frame_size;
        req_.tp_frame_nr = ring_frames;

        // 设置 PACKET_TX_RING 选项
        if (setsockopt(socket_fd_, SOL_PACKET, PACKET_TX_RING, &req_, sizeof(req_)) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to set PACKET_TX_RING option");
        }

        // 映射内存
        ring_buffer_size_ = req_.tp_block_size * req_.tp_block_nr;
        ring_buffer_ = (char*)mmap(NULL, ring_buffer_size_, 
                                  PROT_READ | PROT_WRITE, MAP_SHARED, 
                                  socket_fd_, 0);
        if (ring_buffer_ == MAP_FAILED) {
            close(socket_fd_);
            throw std::runtime_error("Failed to mmap ring buffer");
        }

        current_frame_ = 0;
    }

    ~PacketBatchSender() {
        if (ring_buffer_ != MAP_FAILED) {
            munmap(ring_buffer_, ring_buffer_size_);
        }
        if (socket_fd_ >= 0) {
            close(socket_fd_);
        }
    }

    // 记录要发送的 UDP 包
    bool push(const void* data, size_t size, sockaddr* remote, int addrlen) {
        // 保存数据包信息
        sockaddr* remote_copy = (sockaddr*)malloc(addrlen);
        if (!remote_copy) {
            return false;
        }
        memcpy(remote_copy, remote, addrlen);

        packet_queue_.push_back({data, size, remote_copy, addrlen});
        return true;
    }

    // 构建 IP 和 UDP 头部
    void buildHeaders(char* frame, const sockaddr_in* dest, size_t data_size) {
        // 获取源 IP 地址
        memset(&ifr_, 0, sizeof(ifr_));
        strncpy(ifr_.ifr_name, ifr_.ifr_name, IFNAMSIZ - 1);
        if (ioctl(socket_fd_, SIOCGIFADDR, &ifr_) < 0) {
            throw std::runtime_error("Failed to get interface IP address");
        }
        struct sockaddr_in* src_addr = (struct sockaddr_in*)&ifr_.ifr_addr;
        
        // 以太网帧头部
        struct ethhdr* eth = (struct ethhdr*)frame;
        
        // 获取目标 MAC 地址 (这里简化，实际应使用 ARP)
        memset(&ifr_, 0, sizeof(ifr_));
        strncpy(ifr_.ifr_name, ifr_.ifr_name, IFNAMSIZ - 1);
        if (ioctl(socket_fd_, SIOCGIFHWADDR, &ifr_) < 0) {
            throw std::runtime_error("Failed to get interface MAC address");
        }
        memcpy(eth->h_source, ifr_.ifr_hwaddr.sa_data, ETH_ALEN);
        
        // 这里假设目标 MAC 地址，实际项目中应当通过 ARP 获取
        // 暂时填充网关 MAC（实际应用中应当使用 ARP 协议获取）
        eth->h_dest[0] = 0x00;
        eth->h_dest[1] = 0x00;
        eth->h_dest[2] = 0x00;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0x00;
        
        eth->h_proto = htons(ETH_P_IP);
        
        // IP 头部
        struct iphdr* iph = (struct iphdr*)(frame + sizeof(struct ethhdr));
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_size);
        iph->id = htons(0); // 由内核填充
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0; // 将在发送时由内核计算
        iph->saddr = src_addr->sin_addr.s_addr;
        iph->daddr = dest->sin_addr.s_addr;
        
        // UDP 头部
        struct udphdr* udph = (struct udphdr*)(frame + sizeof(struct ethhdr) + sizeof(struct iphdr));
        udph->source = htons(1234); // 源端口，可配置
        udph->dest = dest->sin_port;
        udph->len = htons(sizeof(struct udphdr) + data_size);
        udph->check = 0; // 将在发送时由内核计算
    }

    // 一次性发送所有数据包
    bool flush() {
        if (packet_queue_.empty()) {
            return true;
        }

        for (const auto& packet : packet_queue_) {
            // 获取当前帧
            struct tpacket_hdr* header = (struct tpacket_hdr*)(ring_buffer_ + current_frame_ * req_.tp_frame_size);
            
            // 等待帧可用
            while (header->tp_status & TP_STATUS_SENDING) {
                // 可以用 poll 替代忙等待
            }
            
            // 准备帧
            header->tp_len = packet.size + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
            header->tp_status = 0;
            
            // 构建帧
            char* frame_start = (char*)header + TPACKET_HDRLEN;
            
            // 构建头部
            if (packet.remote->sa_family == AF_INET) {
                buildHeaders(frame_start, (sockaddr_in*)packet.remote, packet.size);
            } else {
                free(packet.remote);
                continue; // 跳过非 IPv4 地址
            }
            
            // 复制数据
            char* data_ptr = frame_start + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
            memcpy(data_ptr, packet.data, packet.size);
            
            // 设置帧状态为可发送
            header->tp_status = TP_STATUS_SEND_REQUEST;
            
            // 移动到下一帧
            current_frame_ = (current_frame_ + 1) % req_.tp_frame_nr;
            
            free(packet.remote);
        }
        
        // 发送所有帧
        if (sendto(socket_fd_, NULL, 0, 0, NULL, 0) < 0) {
            return false;
        }
        
        packet_queue_.clear();
        return true;
    }
};

