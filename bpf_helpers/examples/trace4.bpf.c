#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

struct {
   __uint(type, BPF_MAP_TYPE_QUEUE);
   __uint(max_entries, 8);
   __uint(value_size, sizeof(__u32));
} ingress SEC(".maps");


SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
   bpf_printk("Hello world");
   void* data_end = (void *)(long)skb->data_end;
   void* data = (void *)(long)skb->data;
   u32 value;
   int err;


   struct ethhdr* eth = (struct ethhdr *)data;
   if ((void *)(eth + 1) > data_end)
       return TC_ACT_OK;

   struct iphdr* iph = (struct iphdr *)(eth + 1);
   if ((void *)(iph + 1) > data_end)
       return TC_ACT_OK;  // Check IP header


   err = bpf_map_push_elem(&ingress, &iph->saddr, 0);
   bpf_printk("Pushed something to queue");
   if (err)
       return TC_ACT_OK;


   err = bpf_map_peek_elem(&ingress, &value);
   bpf_printk("Peeked something in queue");
   if (err)
       return TC_ACT_OK;


   if(value == iph->saddr)
   {
       err = bpf_map_pop_elem(&ingress, &value);
       bpf_printk("Popped something from queue");
       if (err)
           return TC_ACT_OK;
   }


   return TC_ACT_OK;
}


char _license[] SEC("license") = "GPL";

