/* RoCC (Robust Congestion Control)
 */

#include <net/tcp.h>
#include <linux/build_bug.h>

#define ROCC_DEBUG
#define U64_S_TO_US ((u64) 1e6)
#define INIT_MAX_C ((u32) 1e5)
// ^^ This is roughly 1.20 Gbps.

// Should be a power of two so rocc_num_intervals_mask can be set
static const u16 rocc_num_intervals = 16;
// rocc_num_intervals expressed as a mask. It is always equal to
// rocc_num_intervals-1
static const u16 rocc_num_intervals_mask = 15;
static const u32 rocc_min_cwnd = 2;
static const u32 rocc_alpha_segments = 5;
// Maximum tolerable loss rate, expressed as `loss_thresh / 1024`. Calculations
// are faster if things are powers of 2
static const u64 rocc_loss_thresh = 64;
static const u32 rocc_periods_between_large_loss = 8;
static const u32 rocc_history_periods = 8;
static const u32 rocc_timeout_period = 12;
static const u32 rocc_significant_mult_percent = 110;

static const u32 rocc_measurement_interval = 1;

enum rocc_state {
	SLOW_START,
	CONG_AVOID
};

// To keep track of the number of packets acked over a short period of time
struct rocc_interval {
	// Starting time of this interval
	u64 start_us;
	u32 pkts_acked;
	u32 pkts_lost;
	bool app_limited;
	u32 min_rtt_us;
	u32 max_rtt_us;

	// metrics at interval creation time
	u64 ic_rs_prior_mstamp;
	u32 ic_rs_prior_delivered;
	u64 ic_bytes_sent;

	bool processed;
	bool invalid;
};

struct belief_data {
	u64 min_c;  // segments or packets per second
	u64 max_c;  // segments or packets per second
	u32 min_qdel;  // in microseconds
	u64 min_c_lambda;  // segments or packets per second
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

	u64 last_loss_tstamp;
	u32 last_cwnd;
	u32 last_to_last_cwnd;

	struct belief_data *beliefs;

	u64 last_timeout_tstamp;
	u64 last_timeout_minc;
	u64 last_timeout_maxc;

	enum rocc_state state;
};

static void rocc_init(struct sock *sk)
{
	struct rocc_data *rocc = inet_csk_ca(sk);
	u16 i;

	rocc->intervals = kzalloc(sizeof(*(rocc->intervals)) * rocc_num_intervals,
				  GFP_KERNEL);
	for (i = 0; i < rocc_num_intervals; ++i) {
		rocc->intervals[i].start_us = 0;
		rocc->intervals[i].pkts_acked = 0;
		rocc->intervals[i].pkts_lost = 0;
		rocc->intervals[i].app_limited = false;
		rocc->intervals[i].min_rtt_us = U32_MAX;
		rocc->intervals[i].max_rtt_us = 0;

		rocc->intervals[i].ic_rs_prior_mstamp = 0;
		rocc->intervals[i].ic_rs_prior_delivered = 0;
		rocc->intervals[i].ic_bytes_sent = 0;

		rocc->intervals[i].processed = false;
		rocc->intervals[i].invalid = true;
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

	rocc->last_loss_tstamp = 0; // tcp_sk(sk)->tcp_mstamp;
	rocc->last_cwnd = rocc_min_cwnd;
	rocc->last_to_last_cwnd = rocc_min_cwnd;

	rocc->beliefs = kzalloc(sizeof(*(rocc->beliefs)), GFP_KERNEL);
	rocc->beliefs->max_c = INIT_MAX_C;
	// Setting this as U32_MAX and then setting cwnd as U32_MAX causes issues
	// with the kernel... Earlier set as U32_MAX, even though, max_c is u64,
	// keeping it at u32_max so that we can multiply and divide by microseconds.
	rocc->beliefs->min_c = 0;
	rocc->beliefs->min_qdel = 0;
	rocc->beliefs->min_c_lambda = 0;

	rocc->last_timeout_tstamp = 0;
	rocc->last_timeout_minc = 0;
	rocc->last_timeout_maxc = INIT_MAX_C;

	rocc->state = SLOW_START;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	// printk(KERN_INFO "ROCC: Initialized ROCC with max_c %llu", rocc->beliefs->max_c);
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

static bool get_loss_mode(u32 pkts_acked, u32 pkts_lost) {
	bool loss_mode = (u64)pkts_lost * 1024 >
					 (u64)(pkts_acked + pkts_lost) * rocc_loss_thresh;
	return loss_mode;
}

static void update_beliefs(struct sock *sk) {
	struct tcp_sock *tsk = tcp_sk(sk);
	struct rocc_data *rocc = inet_csk_ca(sk);

	u16 st;
	u16 et = rocc->intervals_head;  // end time
	u64 et_tstamp = rocc->intervals[et].start_us;

	u32 this_min_rtt_us;

	u64 st_tstamp;
	u32 cum_pkts_acked = 0;
	// u64 cum_ack_rate;
	u32 window;

	bool this_loss;
	bool this_high_delay;
	bool this_utilized;
	bool cum_utilized;

	struct rocc_interval *this_interval;
	struct belief_data *beliefs = rocc->beliefs;
	u32 rtprop = rocc->min_rtt_us;
	u32 max_jitter = rtprop;

	u64 new_min_c = 0;
	u64 new_max_c = INIT_MAX_C;
	u64 rocc_alpha_rate = (rocc_alpha_segments * rocc_get_mss(tsk) * U64_S_TO_US) / rocc->min_rtt_us;
	u64 max_c_lower_clamp = max_t(u64, 2, rocc_alpha_rate);

	u64 now = et_tstamp;
	u32 time_since_last_timeout = tcp_stamp_us_delta(now, rocc->last_timeout_tstamp);
	bool timeout = time_since_last_timeout > rocc_timeout_period * rocc->min_rtt_us;

	// UPDATE QDEL BELIEFS
	this_interval = &rocc->intervals[et & rocc_num_intervals_mask];
	this_min_rtt_us = this_interval->min_rtt_us;
	if(this_min_rtt_us > rtprop + max_jitter && !(this_interval->invalid)) {
		beliefs->min_qdel = this_min_rtt_us - (rtprop + max_jitter);
	}
	else {
		beliefs->min_qdel = 0;
	}

	// UPDATE LINK RATE BELIEFS
	// The et interval might have just started with very few measurements. So
	// we ignore measurements in that interval (start st at 1 instead of 0). We
	// can perhaps keep a tstamp of the last measurement in that interval?
	for (st = 1; st < rocc_num_intervals; st++) {
		this_interval = &rocc->intervals[(et + st) & rocc_num_intervals_mask];
		if (this_interval->invalid) break;

		this_min_rtt_us = this_interval->min_rtt_us;
		st_tstamp = this_interval->start_us;
		window = tcp_stamp_us_delta(et_tstamp, st_tstamp);

		this_high_delay = this_min_rtt_us > rtprop + max_jitter;
		this_loss = get_loss_mode(this_interval->pkts_acked, this_interval->pkts_lost);
		// TODO: loss was detected in this interval does not mean this interval
		// was utilized. Things were utilized when pkt with sequence number just
		// less than the lost sequence number was sent.
		this_utilized = this_loss || this_high_delay;
		if (st == 1) {
			cum_utilized = this_utilized;
		} else {
			cum_utilized = cum_utilized && this_utilized;
		}

		cum_pkts_acked += this_interval->pkts_acked;
		// cum_ack_rate =
		// 	U64_S_TO_US * cum_pkts_acked / window;

		// current units = MSS/second
		// TODO: check precision loss here.
		new_min_c =
			max_t(u64, new_min_c, (U64_S_TO_US * cum_pkts_acked) / (window + max_jitter));

		if (cum_utilized && st > 1) {
			new_max_c =
				min_t(u64, new_max_c, (U64_S_TO_US * cum_pkts_acked) / (window - max_jitter));
		}
	}

	if(timeout) {
		bool minc_changed = new_min_c > rocc->last_timeout_minc;
		bool maxc_changed = new_max_c < rocc->last_timeout_maxc;
		bool minc_changed_significantly = new_min_c > (rocc_significant_mult_percent * rocc->last_timeout_minc) / 100;
		bool maxc_changed_significantly = (new_max_c * rocc_significant_mult_percent) / 100 < rocc->last_timeout_maxc;
		bool beliefs_invalid = new_max_c < new_min_c;
		bool minc_came_close = minc_changed && beliefs_invalid;
		bool maxc_came_close = maxc_changed && beliefs_invalid;
		bool timeout_minc = !minc_changed && (maxc_came_close || !maxc_changed_significantly);
		bool timeout_maxc = !maxc_changed && (minc_came_close || !minc_changed_significantly);

		if(timeout_minc) {
			beliefs->min_c = new_min_c;
		} else {
			beliefs->min_c = max_t(u64, beliefs->min_c, new_min_c);
		}

		if(timeout_maxc) {
			beliefs->max_c = min_t(u64, (beliefs->max_c * 3) / 2, new_max_c);
		} else {
			beliefs->max_c = min_t(u64, beliefs->max_c, new_max_c);
		}

		rocc->last_timeout_tstamp = now;
		rocc->last_timeout_minc = beliefs->min_c;
		rocc->last_timeout_maxc = beliefs->max_c;
	}
	else {
		beliefs->min_c = max_t(u64, beliefs->min_c, new_min_c);
		beliefs->max_c = min_t(u64, beliefs->max_c, new_max_c);
	}
	beliefs->max_c = max_t(u64, beliefs->max_c, max_c_lower_clamp);
	// printk(KERN_INFO "after update max_c %llu new_max_c %llu", rocc->beliefs->max_c, new_max_c);
}

static void update_beliefs_send(struct sock *sk, const struct rate_sample *rs)
{
	struct rocc_data *rocc = inet_csk_ca(sk);
	struct belief_data *beliefs = rocc->beliefs;
	struct tcp_sock *tsk = tcp_sk(sk);

	u16 st;
	u64 st_tstamp;
	u16 et = rocc->intervals_head;  // end time
	// u64 et_tstamp = rocc->intervals[et].start_us;

	struct rocc_interval *this_interval;
	struct rocc_interval *next_future_interval;
	u64 this_max_rtt_us;
	bool this_loss;
	bool this_high_delay;
	u64 now_bytes_delivered = ((u64) rocc_get_mss(tsk)) * tsk->delivered;
	u64 this_bytes_sent;
	u64 this_min_c_lambda;
	u64 this_interval_length;

	bool this_under_utilized;
	bool cum_under_utilized = true;

	u32 rtprop = rocc->min_rtt_us;
	u32 max_jitter = rtprop;
	u64 new_min_c_lambda = 0;

	this_interval = &rocc->intervals[et & rocc_num_intervals_mask];
	this_max_rtt_us = this_interval->max_rtt_us;
	this_high_delay = this_max_rtt_us > rtprop + max_jitter;
	this_loss = get_loss_mode(this_interval->pkts_acked, this_interval->pkts_lost);
	this_under_utilized = !this_loss && !this_high_delay;
	cum_under_utilized = cum_under_utilized && this_under_utilized;

	// printk(KERN_INFO "update beliefs send begin min_c_lambda %llu", beliefs->min_c_lambda);

	for (st = 1; st < rocc_num_intervals; st++) {
		// This for loop iterates over intervals in descending order of time.
		this_interval = &rocc->intervals[(et + st) & rocc_num_intervals_mask];
		if (this_interval->invalid) break;

		next_future_interval = &rocc->intervals[(et + st - 1) & rocc_num_intervals_mask];
		st_tstamp = this_interval->start_us;

		this_max_rtt_us = this_interval->max_rtt_us;
		this_high_delay = this_max_rtt_us > rtprop + max_jitter;
		this_loss = get_loss_mode(this_interval->pkts_acked, this_interval->pkts_lost);
		this_under_utilized = !this_loss && !this_high_delay;
		cum_under_utilized = cum_under_utilized && this_under_utilized;

		// We only consider this interval if all packets sent were 1 RTT before
		// now.
		if (next_future_interval->ic_bytes_sent > now_bytes_delivered) continue;

		// Stop if we have already considered this and past intervals.
		if (this_interval->processed) break;
		this_interval->processed = true;

		// If we saw any utilization signals then we stop updating min_c_lambda
		if (!cum_under_utilized) break;

		BUILD_BUG_ON(rocc_measurement_interval != 1);
		this_bytes_sent = next_future_interval->ic_bytes_sent - this_interval->ic_bytes_sent;
		this_interval_length = tcp_stamp_us_delta(next_future_interval->start_us, this_interval->start_us);
		this_min_c_lambda = ((this_bytes_sent * U64_S_TO_US) / rocc_get_mss(tsk)) / (this_interval_length + max_jitter);
		// ^^ We divide by rocc_get_mss(tsk) to convert from bytes to segments or packets.
		new_min_c_lambda = max_t(u64, new_min_c_lambda, this_min_c_lambda);
	}

	beliefs->min_c_lambda = max_t(u64, beliefs->min_c_lambda, new_min_c_lambda);
}

void print_beliefs(struct sock *sk){
	struct rocc_data *rocc = inet_csk_ca(sk);
	struct belief_data *beliefs = rocc->beliefs;
	struct tcp_sock *tsk = tcp_sk(sk);

	u16 i, id, nid;
	u32 window = 0;
	u32 ic_rs_window = 0;
	s32 delivered_delta = 0;
	s32 sent_delta_pkts = 0;

	printk(KERN_INFO "rocc min_c %llu max_c %llu min_qdel %u min_c_lambda %llu",
		   beliefs->min_c, beliefs->max_c, beliefs->min_qdel,
		   beliefs->min_c_lambda);
	for (i = 0; i < rocc_num_intervals; ++i) {
		id = (rocc->intervals_head + i) & rocc_num_intervals_mask;
		nid = (id - 1) & rocc_num_intervals_mask;  // next id
		if (i >= 1) {
			window = tcp_stamp_us_delta(rocc->intervals[nid].start_us,
										rocc->intervals[id].start_us);
			ic_rs_window =
				tcp_stamp_us_delta(rocc->intervals[nid].ic_rs_prior_mstamp,
								   rocc->intervals[id].ic_rs_prior_mstamp);
			delivered_delta = (rocc->intervals[nid].ic_rs_prior_delivered -
							   rocc->intervals[id].ic_rs_prior_delivered);
			sent_delta_pkts = (((s64)rocc->intervals[nid].ic_bytes_sent) -
							   rocc->intervals[id].ic_bytes_sent) /
							  rocc_get_mss(tsk);
		}
		printk(KERN_INFO
			   "rocc intervals start_us %llu window %u acked %u lost %u "
			   "ic_rs_prior_mstamp %llu ic_rs_prior_delivered %u "
			   "ic_rs_window %u delivered_delta %d "
			   "app_limited %d min_rtt_us %u max_rtt_us %u "
			   "i %u id %u invalid %d processed %d "
			   "ic_bytes_sent %llu sent_delta_pkts %d",
			   rocc->intervals[id].start_us, window,
			   rocc->intervals[id].pkts_acked, rocc->intervals[id].pkts_lost,
			   rocc->intervals[id].ic_rs_prior_mstamp,
			   rocc->intervals[id].ic_rs_prior_delivered, ic_rs_window,
			   delivered_delta, (int)rocc->intervals[id].app_limited,
			   rocc->intervals[id].min_rtt_us, rocc->intervals[id].max_rtt_us,
			   i, id, rocc->intervals[id].invalid,
			   rocc->intervals[id].processed, rocc->intervals[id].ic_bytes_sent,
			   sent_delta_pkts);
	}
}

static void rocc_process_sample(struct sock *sk, const struct rate_sample *rs)
{
	struct rocc_data *rocc = inet_csk_ca(sk);
	struct tcp_sock *tsk = tcp_sk(sk);
	struct belief_data *beliefs = rocc->beliefs;
	u32 rtt_us;
	u16 i, id;
	u32 hist_us;
	u64 timestamp;
	u32 interval_length;
	// Number of packets acked and lost in the last `hist_us`
	u32 pkts_acked, pkts_lost;
	bool loss_mode, app_limited;

	u64 rocc_alpha_rate;
	u32 latest_inflight_segments = rs->prior_in_flight; // upper bound on bottleneck queue size.

	// printk(KERN_INFO "rocc rate_sample rs_timestamp %llu tcp_timestamp %llu delivered %d", tsk->tcp_mstamp, rs->prior_mstamp);
	// printk(KERN_INFO "rocc rate_sample acked_sacked %u last_end_seq %u snd_nxt % u rcv_nxt %u", rs->acked_sacked, rs->last_end_seq, tsk->snd_nxt, tsk->rcv_nxt);

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
		hist_us = rocc_history_periods * rocc->min_rtt_us;

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
		rocc->intervals[rocc->intervals_head].min_rtt_us = rs->rtt_us;
		rocc->intervals[rocc->intervals_head].max_rtt_us = rs->rtt_us;
		rocc->intervals[rocc->intervals_head].ic_bytes_sent = tsk->bytes_sent;
		rocc->intervals[rocc->intervals_head].ic_rs_prior_mstamp = rs->prior_mstamp;
		rocc->intervals[rocc->intervals_head].ic_rs_prior_delivered = rs->prior_delivered;
		rocc->intervals[rocc->intervals_head].processed = false;
		rocc->intervals[rocc->intervals_head].invalid = false;
		update_beliefs(sk);
		update_beliefs_send(sk, rs);
		print_beliefs(sk);
	}
	else {
		rocc->intervals[rocc->intervals_head].pkts_acked += rs->acked_sacked;
		rocc->intervals[rocc->intervals_head].pkts_lost += rs->losses;
		rocc->intervals[rocc->intervals_head].app_limited |= rs->is_app_limited;
		// TODO: check what kind of aggregation we want here.
		rocc->intervals[rocc->intervals_head].min_rtt_us =
			min_t(u32, (u32) rs->rtt_us, rocc->intervals[rocc->intervals_head].min_rtt_us);
		rocc->intervals[rocc->intervals_head].max_rtt_us =
			max_t(u32, (u32) rs->rtt_us, rocc->intervals[rocc->intervals_head].max_rtt_us);
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
	rocc_alpha_rate = (rocc_alpha_segments * rocc_get_mss(tsk) * U64_S_TO_US) / rocc->min_rtt_us;
	if(loss_mode) rocc->state = CONG_AVOID;

	if (tcp_stamp_us_delta(timestamp, rocc->last_update_tstamp) >= rocc->min_rtt_us) {
		rocc->last_update_tstamp = timestamp;

		if(rocc->state == SLOW_START) {
			if(beliefs->min_qdel > 0) {
				sk->sk_pacing_rate = (beliefs->min_c * rocc_get_mss(tsk)) / 2;
			}
			else {
				sk->sk_pacing_rate = 2 * beliefs->min_c * rocc_get_mss(tsk);
			}
		}
		else {
			if(rocc->state != CONG_AVOID) {
				printk(KERN_ERR "Invalid state for rocc: %d", rocc->state);
			}
			/**
			 * The 3 is basically R + D + quantization error.
			 * In the kernel the error is 0. Thus use 2 instead of 3.
			r_f = max alpha,
			if (+ 1bq_belief + -1alpha > 0):
				+ 1alpha
			else:
				+ 3min_c_lambda + 1alpha
			*/
			if(latest_inflight_segments > 10 * rocc_alpha_segments) {
				// ^^ we are okay losing 10 alpha segments every probe
				sk->sk_pacing_rate = rocc_alpha_rate;
			}
			else {
				sk->sk_pacing_rate = 2 * beliefs->min_c_lambda * rocc_get_mss(tsk) + rocc_alpha_rate;
			}
		}

		// jitter + rtprop = 2 * rocc->min_rtt_us
		tsk->snd_cwnd = (2 * beliefs->max_c * (2 * rocc->min_rtt_us)) / U64_S_TO_US;

		// lower bound clamps
		tsk->snd_cwnd = max_t(u32, tsk->snd_cwnd, rocc_alpha_segments);
		sk->sk_pacing_rate = max_t(u64, sk->sk_pacing_rate, rocc_alpha_rate);

#ifdef ROCC_DEBUG
		printk(KERN_INFO
			   "rocc flow %u cwnd %u pacing %lu rtt %u mss %u timestamp %llu "
			   "interval %ld state %d",
			   rocc->id, tsk->snd_cwnd, sk->sk_pacing_rate, rtt_us,
			   tsk->mss_cache, timestamp, rs->interval_us, rocc->state);
		printk(KERN_INFO
			   "rocc pkts_acked %u hist_us %u pacing %lu loss_happened %d "
			   "app_limited %d rs_limited %d latest_inflight_segments %u "
			   "delivered_bytes %llu",
			   pkts_acked, hist_us, sk->sk_pacing_rate,
			   (int)rocc->loss_happened, (int)app_limited,
			   (int)rs->is_app_limited, latest_inflight_segments,
			   ((u64) rocc_get_mss(tsk)) * tsk->delivered);
		// print_beliefs(sk);
#endif
	}
	// printk(KERN_INFO "rocc_process_sample got rtt_us %lu", rs->rtt_us);
	// printk(KERN_INFO "rocc_process_sample cwnd %u pacing %lu", tsk->snd_cwnd, sk->sk_pacing_rate);
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
	.name = "slow_paced",
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
