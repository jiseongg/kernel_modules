#include <asm/uaccess.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/proc_fs.h>
#include <linux/tcp.h>
#include <uapi/linux/netfilter_ipv4.h>


/** proc file system entry
 * author: jiseongg
 * date: 2020.12.08
 */
#define PROC_DIR "group3"
#define RULE_ADD "add"
#define RULE_DEL "del"
#define RULE_SHOW "show"
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file_add;
static struct proc_dir_entry *proc_file_del;
static struct proc_dir_entry *proc_file_show;

//일단 가장 처음 echo 1 > /rpoc/sys/net/ipv4/ip_forward=1로 키기 

int I_ports[10];
int O_ports[10];
int P_ports[10];
int F_ports[10];

//I: NF_INET_PRE_ROUTING에서, inbound 통과는 아래 함수
//O: NF_INET_POST_ROUTING에서, O_ports 있으면 통과/drop
//F: NF_INET_FORWARD에서, F_ports 있으면 주소 바꾸기 
//P: NF_INET_PRE_ROUTING에서, proxy는 skb접근해서 ip주소 바꾸기

//inbound drop hook function
static unsigned int my_hook_accept_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state * state){
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	unsigned int saddr = ih->saddr;
	unsigned int daddr = ih->daddr;
	unsigned int sport = th->source;
	unsigned int dport = th->dest;

	//만약 I_ports에 dport가 있으면 return NF_DROP;
	//맞게 printk 문해서 dmesg 출력
	return NF_ACCEPT;
}

//이걸 inbound, outbound, forward, proxy 마다 만들면 될듯
//이건 inbound용
static struct nf_hook_ops my_nf_ops = {
	.hook = my_hook_accept_fn,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FILTER
};


/** proc file system entry
 * author: jiseongg
 * date: 2020.12.08
 */
static int my_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "OPEN %s!\n", file->f_path.dentry->d_name.name);
	return 0;
}

static ssize_t rule_add(struct file *file,
		const char __user *user_buffer,
		size_t count,
		loff_t *ppos) 
{
	return count;
}

static const struct file_operations add_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = rule_add
};

static ssize_t rule_del(struct file *file,
		const char __user *user_buffer,
		size_t count,
		loff_t *ppos) 
{
	return count;
}

static const struct file_operations del_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = rule_del
};

static ssize_t rule_show(struct file *file,
		char __user *user_buffer,
		size_t len,
		loff_t *ppos) 
{
	// ret is amount of data not written
	/*
	ret = copy_to_user(user_buffer, rule_str, cnt);
	printk(KERN_INFO "ppos: %lld", *ppos);
	*ppos += cnt - ret;
	printk(KERN_INFO "ppos: %lld", *ppos);
	if (*ppos > cnt){
		return 0;
	} else {
		return cnt;
	}
	*/
	return 0;
}

static const struct file_operations show_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.read = rule_show
};

static int __init simple_init(void)
{
	printk(KERN_INFO "Netfilter loaded!\n");

	proc_dir = proc_mkdir(PROC_DIR, NULL);
	proc_file_add = proc_create(RULE_ADD, 0600, proc_dir, &add_fops);
	proc_file_del = proc_create(RULE_DEL, 0600, proc_dir, &add_fops);
	proc_file_show = proc_create(RULE_SHOW, 0600, proc_dir, &show_fops);

	//nf_register_hook(&my_nf_hops);
	
	return 0;
}

static void __exit simple_exit(void)
{
	printk(KERN_INFO "Unloading netfilter... \n");
	//nf_unregister_hook(&my_nf_ops);

	proc_remove(proc_file_add);
	proc_remove(proc_file_del);
	proc_remove(proc_file_show);
	proc_remove(proc_dir);

	printk(KERN_INFO "\tSuccessfully removed!\n");
	return;
}

module_init(simple_init);
module_exit(simple_exit);

MODULE_AUTHOR("Hyokyung, Jiseongg");
MODULE_DESCRIPTION("File system profiling module");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
