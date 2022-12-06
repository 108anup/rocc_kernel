/* RoCC (Robust Congestion Control)
 */

#include <net/tcp.h>

#define ROCC_DEBUG

// Should be a power of two so rocc_num_intervals_mask can be set
static const u16 rocc_num_intervals = 16;
// rocc_num_intervals expressed as a mask. It is always equal to
// rocc_num_intervals-1
static const u16 rocc_num_intervals_mask = 15;
static const u32 rocc_min_cwnd = 2;
// Maximum tolerable loss rate, expressed as `loss_thresh / 1024`. Calculations
// are faster if things are powers of 2
static const u64 rocc_loss_thresh = 64;

// To keep track of the number of packets acked over a short period of time
struct rocc_interval {
	// Starting time of this interval
	u64 start_us;
	u32 pkts_acked;
	u32 pkts_lost;
	bool app_limited;
};

static u32 id = 0;
struct rocc_data {
	// Circular queue of intervals
	struct rocc_interval *intervals;
	// Index of the last interval to be added
	u16 intervals_head;

	u32 min_rtt_us;

	// debug helper
	u32 id;

	u32 last_decrease_seq;
	bool loss_happened;

	u64 last_update_tstamp;
};

static void rocc_init(struct sock *sk)
{
	struct rocc_data *rocc = inet_csk_ca(sk);
	u16 i;

	rocc->intervals = kzalloc(sizeof(struct rocc_interval) * rocc_num_intervals,
				  GFP_KERNEL);
	for (i = 0; i < rocc_num_intervals; ++i) {
		rocc->intervals[i].start_us = 0;
		rocc->intervals[i].pkts_acked = 0;
		rocc->intervals[i].pkts_lost = 0;
		rocc->intervals[i].app_limited = false;
	}
	rocc->intervals_head = 0;

	rocc->min_rtt_us = U32_MAX;
	++id;
	rocc->id = id;
	// At connection setup, assume just decreased.
	// We don't expect loss during initial part of slow start anyway.
	rocc->last_decrease_seq = tcp_sk(sk)->snd_nxt;

	// We want update to happen if it hasn't happened since Rm time.
	// Setting last time as 0 in the beginning should allow running cwnd update
	// the first time as long as min_rtt_us < timestamp.
	rocc->last_update_tstamp = 0; // tcp_sk(sk)->tcp_mstamp;
	rocc->loss_happened = false;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

static u32 rocc_get_mss(struct tcp_sock *tsk)
{
	// TODO: Figure out if mss_cache is the one to use
	return tsk->mss_cache;
}

/* was the rocc struct fully inited */
static bool rocc_valid(struct rocc_data *rocc)
{
	return (rocc && rocc->intervals);
}

static void rocc_process_sample(struct sock *sk, const struct rate_sample *rs)
{
	struct rocc_data *rocc = inet_csk_ca(sk);
	struct tcp_sock *tsk = tcp_sk(sk);
	u32 rtt_us;
	u16 i, id;
	u32 hist_us;
	u64 timestamp;
	u32 interval_length;
	// Number of packets acked and lost in the last `hist_us`
	u32 pkts_acked, pkts_lost;
	u32 target_cwnd;
	u32 cwnd;
	bool loss_mode, app_limited;
	bool is_new_congestion_event;

	if (!rocc_valid(rocc))
		return;

	// Is rate sample valid?
	if (rs->delivered < 0 || rs->interval_us < 0)
		return;

	// Get initial RTT - as measured by SYN -> SYN-ACK.  If information
        // does not exist - use U32_MAX as RTT
	if (tsk->srtt_us) {
		rtt_us = max(tsk->srtt_us >> 3, 1U);
	} else {
		rtt_us = U32_MAX;
	}

	if (rtt_us < rocc->min_rtt_us)
		rocc->min_rtt_us = rtt_us;

	if (rocc->min_rtt_us == U32_MAX)
		hist_us = U32_MAX;
	else
		hist_us = 2 * rocc->min_rtt_us;

	// Update intervals
	timestamp = tsk->tcp_mstamp; // Most recent send/receive

	// The factor of 2 gives some headroom so that we always have
	// sufficient history. We end up storing more history than needed, but
	// that's ok
	interval_length = 2 * hist_us / rocc_num_intervals + 1; // round up
	if (rocc->intervals[rocc->intervals_head].start_us + interval_length < timestamp) {
		// Push the buffer
		rocc->intervals_head = (rocc->intervals_head - 1) & rocc_num_intervals_mask;
		rocc->intervals[rocc->intervals_head].start_us = timestamp;
		rocc->intervals[rocc->intervals_head].pkts_acked = rs->acked_sacked;
		rocc->intervals[rocc->intervals_head].pkts_lost = rs->losses;
		rocc->intervals[rocc->intervals_head].app_limited = rs->is_app_limited;
	}
	else {
		rocc->intervals[rocc->intervals_head].pkts_acked += rs->acked_sacked;
		rocc->intervals[rocc->intervals_head].pkts_lost += rs->losses;
		rocc->intervals[rocc->intervals_head].app_limited |= rs->is_app_limited;
	}

	// Find the statistics from the last `hist` seconds
	pkts_acked = 0;
	pkts_lost = 0;
	app_limited = false;
	for (i = 0; i < rocc_num_intervals; ++i) {
		id = (rocc->intervals_head + i) & rocc_num_intervals_mask;
		pkts_acked += rocc->intervals[id].pkts_acked;
		pkts_lost += rocc->intervals[id].pkts_lost;
		app_limited |= rocc->intervals[id].app_limited;
		if (rocc->intervals[id].start_us + hist_us < timestamp) {
			break;
		}
	}

	loss_mode = (u64) pkts_lost * 1024 > (u64) (pkts_acked + pkts_lost) * rocc_loss_thresh;
	is_new_congestion_event = after(rs->last_end_seq, rocc->last_decrease_seq);
	if(loss_mode && is_new_congestion_event) {
		rocc->loss_happened = true;
	}

	if (timestamp - rocc->last_update_tstamp >= rocc->min_rtt_us) {
		// Propagation delay (Rm) worth of time has elapsed since last cwnd update,
		// time to make a new update to cwnd.

		// CCMATIC RULE
		/**
		 * if(Ld_f[n][t] > Ld_f[n][t-1]):
		 *     expr = 1c_f[n][t-1] + 0(S_f[n][t-1]-S_f[n][t-3]) + -1alpha
		 * else:
		 *     expr = 1/2c_f[n][t-1] + 1/2(S_f[n][t-1]-S_f[n][t-3]) + 1alpha
		 *
		 * if(1c_f[n][t-1] + 0(S_f[n][t-1]-S_f[n][t-3]) + -1expr + 0Indicator(Ld_f[n][t] > Ld_f[n][t-1]) > 0):
		 *     c_f[n][t] = max(alpha, 0c_f[n][t-1] + 1expr + 0(S_f[n][t-1]-S_f[n][t-3]) + 0alpha)
		 * else:
		 *     c_f[n][t] = max(alpha, 1c_f[n][t-1] + 0expr + 0(S_f[n][t-1]-S_f[n][t-3]) + 1alpha)
		*/

		// TARGET CWND
		if(rocc->loss_happened) {
			rocc->last_decrease_seq = tsk->snd_nxt;
			target_cwnd = (tsk->snd_cwnd) - 1;
		}
		else {
			target_cwnd = (tsk->snd_cwnd + pkts_acked)/2 + 1;
		}

		// UPDATE CWND
		if (tsk->snd_cwnd > target_cwnd) {
			cwnd = target_cwnd;
			// Do not decrease cwnd if app limited
			if (app_limited && cwnd < tsk->snd_cwnd) {
				cwnd = tsk->snd_cwnd;
			}
			// Lower bound clamp
			cwnd = max(cwnd, rocc_min_cwnd);
			tsk->snd_cwnd = cwnd;
		}
		else {
			tsk->snd_cwnd = tsk->snd_cwnd + 1;
		}

		sk->sk_pacing_rate = 1000000 * (u64) cwnd * rocc_get_mss(tsk) / rocc->min_rtt_us;

#ifdef ROCC_DEBUG
		printk(KERN_INFO "rocc flow %u cwnd %u pacing %lu rtt %u mss %u timestamp %llu interval %ld", rocc->id, tsk->snd_cwnd, sk->sk_pacing_rate, rtt_us, tsk->mss_cache, timestamp, rs->interval_us);
		printk(KERN_INFO "rocc pkts_acked %u hist_us %u pacing %lu loss_happened %d app_limited %d rs_limited %d", pkts_acked, hist_us, sk->sk_pacing_rate, (int)rocc->loss_happened, (int)app_limited, (int)rs->is_app_limited);
		// for (i = 0; i < rocc_num_intervals; ++i) {
		// 	id = (rocc->intervals_head + i) & rocc_num_intervals_mask;
		// 	printk(KERN_INFO "rocc intervals %llu acked %u lost %u app_limited %d i %u id %u", rocc->intervals[id].start_us, rocc->intervals[id].pkts_acked, rocc->intervals[id].pkts_lost, (int)rocc->intervals[id].app_limited, i, id);
		// }
#endif
		// Set state for next cwnd update
		rocc->last_update_tstamp = timestamp;
		rocc->loss_happened = false;
	}
}

static void rocc_release(struct sock *sk)
{
	struct rocc_data *rocc = inet_csk_ca(sk);
	kfree(rocc->intervals);
}

static u32 rocc_ssthresh(struct sock *sk)
{
	return TCP_INFINITE_SSTHRESH; /* ROCC does not use ssthresh */
}

static void rocc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
}

static struct tcp_congestion_ops tcp_rocc_cong_ops __read_mostly = {
	.flags = TCP_CONG_NON_RESTRICTED,
	.name = "aitd_combad_rm",
	.owner = THIS_MODULE,
	.init = rocc_init,
	.release	= rocc_release,
	.cong_control = rocc_process_sample,
	/* Keep the windows static */
	/* Since RoCC ccmatic does reduce cwnd on loss. We use reno's undo method.
	 */
	.undo_cwnd = tcp_reno_undo_cwnd,
	/* Slow start threshold will not exist */
	 .ssthresh = rocc_ssthresh,
	.cong_avoid = rocc_cong_avoid,
};

/* Kernel module section */

static int __init rocc_register(void)
{
	BUILD_BUG_ON(sizeof(struct rocc_data) > ICSK_CA_PRIV_SIZE);
#ifdef ROCC_DEBUG
	printk(KERN_INFO "rocc init reg\n");
#endif
	return tcp_register_congestion_control(&tcp_rocc_cong_ops);
}

static void __exit rocc_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_rocc_cong_ops);
}

module_init(rocc_register);
module_exit(rocc_unregister);

MODULE_AUTHOR("Venkat Arun <venkatarun95@gmail.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP RoCC CCmatic (Robust Congestion Control CCmatic)");
