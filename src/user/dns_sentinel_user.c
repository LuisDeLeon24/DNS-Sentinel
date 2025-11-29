#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <pthread.h>

struct domain_key { __u32 ip; __u32 hash; };

#define MAX_DOMAINS 16000
#define MAX_RECENT_DOMAINS 10

struct domain_cache_entry { __u32 hash; char domain[256]; };
static struct domain_cache_entry domain_cache[MAX_DOMAINS];
static int domain_cache_count = 0;
static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;

struct recent_domains {
    __u32 hashes[MAX_RECENT_DOMAINS];
    int count;
} recent[MAX_DOMAINS]; // buffer circular simple por IP

static pid_t sniffer_pid = 0;

void cleanup_sniffer() {
    if (sniffer_pid > 0) {
        printf("\n[*] Stopping DNS sniffer...\n");
        kill(sniffer_pid, SIGTERM);
        waitpid(sniffer_pid, NULL, 0);
    }
}

void signal_handler(int sig) {
    cleanup_sniffer();
    exit(0);
}

void start_sniffer(const char *iface) {
    sniffer_pid = fork();
    
    if (sniffer_pid == 0) {
        char *args[] = {"python3", "dns_sniffer.py", (char*)iface, NULL};
        execvp("python3", args);
        fprintf(stderr, "[!] Error: Cannot start dns_sniffer.py\n");
        exit(1);
    } else if (sniffer_pid < 0) {
        fprintf(stderr, "[!] Error: fork() failed\n");
        exit(1);
    }

    printf("[*] DNS sniffer started (PID: %d)\n", sniffer_pid);
    sleep(1);
}


void cache_insert_local(__u32 hash, const char *domain) {
    pthread_mutex_lock(&cache_lock);
    for (int i = 0; i < domain_cache_count; i++) {
        if (domain_cache[i].hash == hash) {
            pthread_mutex_unlock(&cache_lock);
            return;
        }
    }

    if (domain_cache_count < MAX_DOMAINS) {
        domain_cache[domain_cache_count].hash = hash;
        snprintf(domain_cache[domain_cache_count].domain, sizeof(domain_cache[0].domain), "%s", domain);
        domain_cache_count++;
    }
    pthread_mutex_unlock(&cache_lock);
}

const char* cache_get_local(__u32 hash) {
    const char *res = NULL;
    pthread_mutex_lock(&cache_lock);
    for (int i = 0; i < domain_cache_count; i++) {
        if (domain_cache[i].hash == hash) {
            res = domain_cache[i].domain;
            break;
        }
    }
    pthread_mutex_unlock(&cache_lock);
    return res;
}

void *cache_reload_thread(void *arg) {
    (void)arg;
    const char *path = "/tmp/dns_domains.txt";

    FILE *f = fopen(path, "r");
    if (!f)
        f = fopen(path, "w+");  

    fseek(f, 0, SEEK_END);
    long last_pos = ftell(f);
    fclose(f);

    while (1) {
        FILE *rf = fopen(path, "r");
        if (!rf) {
            sleep(2);
            continue;
        }

        fseek(rf, last_pos, SEEK_SET);

        char line[512];
        while (fgets(line, sizeof(line), rf)) {
            char domain[256];
            unsigned long h;

            if (sscanf(line, "%lu %255s", &h, domain) == 2) {
                cache_insert_local((__u32)h, domain);
            }
        }

        last_pos = ftell(rf);
        fclose(rf);

        sleep(1);
    }

    return NULL;
}

int count_domains_for_ip(int domain_fd, __u32 ip, __u32 out_hashes[], int *out_count) {
    struct domain_key key = {0}, next_key;
    int pos = 0;
    while (bpf_map_get_next_key(domain_fd, &key, &next_key) == 0) {
        if (next_key.ip == ip) {
            if (pos < 256) out_hashes[pos++] = next_key.hash;
        }
        key = next_key;
    }
    *out_count = pos;
    return pos;
}

int calc_score(int qps, int domains) { 
    return qps + domains * 3; 
}

const char* calc_status(int score) {
    if (score > 100) return "Dangerous";
    if (score > 40) return "Suspicious";
    return "Normal";
}

int main(int argc, char **argv) {
    if (argc < 2) { 
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]); 
        return 1; 
    }
    
    const char *iface = argv[1];
    int ifindex = if_nametoindex(iface);
    if (!ifindex) { 
        fprintf(stderr, "Interface not found: %s\n", iface); 
        return 1; 
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("[*] Starting DNS Sentinel...\n");
    start_sniffer(iface);

    pthread_t thr;
    pthread_create(&thr, NULL, cache_reload_thread, NULL);

    struct bpf_object *obj = bpf_object__open_file("dns_sentinel_kern.o", NULL);
    if (!obj) { 
        fprintf(stderr, "bpf_object__open_file failed\n"); 
        cleanup_sniffer();
        return 1; 
    }
    
    if (bpf_object__load(obj)) { 
        fprintf(stderr, "bpf_object__load failed\n"); 
        cleanup_sniffer();
        return 1; 
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "dns_sentinel");
    if (!prog) { 
        fprintf(stderr, "Program dns_sentinel not found\n"); 
        cleanup_sniffer();
        return 1; 
    }
    
    if (bpf_program__attach_xdp(prog, ifindex) < 0) { 
        fprintf(stderr, "attach_xdp failed\n"); 
        cleanup_sniffer();
        return 1; 
    }

    int counter_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "dns_counter"));
    int last_fd    = bpf_map__fd(bpf_object__find_map_by_name(obj, "last_seen"));
    int domain_fd  = bpf_map__fd(bpf_object__find_map_by_name(obj, "domain_seen"));
    
    if (counter_fd < 0 || last_fd < 0 || domain_fd < 0) { 
        fprintf(stderr, "Error getting map file descriptors\n"); 
        cleanup_sniffer();
        return 1; 
    }

    printf("[+] XDP loaded on %s\n", iface);
    printf("[+] Monitoring DNS traffic...\n\n");

    char ip_str[INET_ADDRSTRLEN];

    while (1) {
        system("clear");
        printf("┌─────────────── DNS Sentinel ─────────────────┐\n");
        printf("│ Real-time monitoring (XDP + eBPF)            │\n");
        printf("└──────────────────────────────────────────────┘\n\n");

        printf("IP                     Domains    Score   Status\n");
        printf("-----------------------------------------------------\n");

        __u32 key = 0, next_key;
        __u64 count;
        __u64 now = time(NULL);

        while (bpf_map_get_next_key(counter_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(counter_fd, &next_key, &count) == 0) {

                inet_ntop(AF_INET, &next_key, ip_str, sizeof(ip_str));

                __u64 last;
                int qps = 0;
                if (bpf_map_lookup_elem(last_fd, &next_key, &last) == 0) {
                    __u64 diff = now - (last / 1000000000ULL);
                    if (diff <= 1) qps = count;
                }

                __u32 hashes[256]; 
                int dom_count = 0;
                count_domains_for_ip(domain_fd, next_key, hashes, &dom_count);

                int score = calc_score(qps, dom_count);
                const char *state = calc_status(score);

                printf("%-15s  %-5d  %-10d  %-6d  %s\n",
                        ip_str, qps, dom_count, score, state);

                struct recent_domains *r = &recent[next_key % MAX_DOMAINS];
                for (int i = 0; i < dom_count; i++) {
                    int exists = 0;
                    for (int j = 0; j < r->count; j++)
                        if (r->hashes[j] == hashes[i]) { exists = 1; break; }
                    if (!exists) {
                        if (r->count < MAX_RECENT_DOMAINS) {
                            r->hashes[r->count++] = hashes[i];
                        } else {
                            for (int j = 1; j < MAX_RECENT_DOMAINS; j++)
                                r->hashes[j-1] = r->hashes[j];
                            r->hashes[MAX_RECENT_DOMAINS-1] = hashes[i];
                        }
                    }
                }

                if (r->count > 0) {
                    printf("\nDomains requested:\n");
                    for (int i = 0; i < r->count; i++) {
                        const char *d = cache_get_local(r->hashes[i]);
                        if (d)
                            printf(" - %s\n", d);
                    }
                    int missing = 0;
                    for (int i = 0; i < r->count; i++) {
                        const char *d = cache_get_local(r->hashes[i]);
                        if (!d) {
                            printf(" - [hash: %u]\n", r->hashes[i]);
                            missing++;
                        }
                    }
                    if (missing > 0)
                        printf("\n");
                }
            }
            key = next_key;
        }

        sleep(2);
    }

    cleanup_sniffer();
    return 0;
}

