package collector

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/mqliang/libipvs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/process"
)

// Signals.
const (
	SIGRTMIN = syscall.Signal(32)
	SIGJSON  = syscall.Signal(SIGRTMIN + 4)
)

// KAStats type.
type KAStats struct {
	Data  Data  `json:"data"`
	Stats Stats `json:"stats"`
}

// Data type.
type Data struct {
	Iname                string   `json:"iname"`
	DontTrackPrimary     int      `json:"dont_track_primary"`
	SkipCheckAdvAddr     int      `json:"skip_check_adv_addr"`
	StrictMode           int      `json:"strict_mode"`
	VmacIfname           string   `json:"vmac_ifname"`
	IfpIfname            string   `json:"ifp_ifname"`
	MasterPriority       int      `json:"master_priority"`
	LastTransition       float64  `json:"last_transition"`
	GarpDelay            int      `json:"garp_delay"`
	GarpRefresh          int      `json:"garp_refresh"`
	GarpRep              int      `json:"garp_rep"`
	GarpRefreshRep       int      `json:"garp_refresh_rep"`
	GarpLowerPrioDelay   int      `json:"garp_lower_prio_delay"`
	GarpLowerPrioRep     int      `json:"garp_lower_prio_rep"`
	LowerPrioNoAdvert    int      `json:"lower_prio_no_advert"`
	HigherPrioSendAdvert int      `json:"higher_prio_send_advert"`
	Vrid                 int      `json:"vrid"`
	BasePriority         int      `json:"base_priority"`
	EffectivePriority    int      `json:"effective_priority"`
	Vipset               bool     `json:"vipset"`
	PromoteSecondaries   bool     `json:"promote_secondaries"`
	AdverInt             int      `json:"adver_int"`
	MasterAdverInt       int      `json:"master_adver_int"`
	Accept               int      `json:"accept"`
	Nopreempt            bool     `json:"nopreempt"`
	PreemptDelay         int      `json:"preempt_delay"`
	State                int      `json:"state"`
	Wantstate            int      `json:"wantstate"`
	Version              int      `json:"version"`
	SMTPAlert            bool     `json:"smtp_alert"`
	Vips                 []string `json:"vips"`
	AuthType             int      `json:"auth_type"`
	AuthData             string   `json:"auth_data"`
}

// Stats type.
type Stats struct {
	AdvertRcvd        int `json:"advert_rcvd"`
	AdvertSent        int `json:"advert_sent"`
	BecomeMaster      int `json:"become_master"`
	ReleaseMaster     int `json:"release_master"`
	PacketLenErr      int `json:"packet_len_err"`
	AdvertIntervalErr int `json:"advert_interval_err"`
	IPTTLErr          int `json:"ip_ttl_err"`
	InvalidTypeRcvd   int `json:"invalid_type_rcvd"`
	AddrListErr       int `json:"addr_list_err"`
	InvalidAuthtype   int `json:"invalid_authtype"`
	AuthtypeMismatch  int `json:"authtype_mismatch"`
	AuthFailure       int `json:"auth_failure"`
	PriZeroRcvd       int `json:"pri_zero_rcvd"`
	PriZeroSent       int `json:"pri_zero_sent"`
}

// KACollector type.
type KACollector struct {
	metrics map[string]*prometheus.Desc
	handle  libipvs.IPVSHandle
	mutex   sync.Mutex
}

// NewKACollector creates an KACollector.
func NewKACollector() (*KACollector, error) {
	coll := &KACollector{}

	labelsVrrp := []string{"name", "intf", "vrid"}
	metrics := map[string]*prometheus.Desc{
		"keepalived_up":                       prometheus.NewDesc("keepalived_up", "Status", nil, nil),
		"keepalived_vrrp_advert_rcvd":         prometheus.NewDesc("keepalived_vrrp_advert_rcvd", "Advertisements received", labelsVrrp, nil),
		"keepalived_vrrp_advert_sent":         prometheus.NewDesc("keepalived_vrrp_advert_sent", "Advertisements sent", labelsVrrp, nil),
		"keepalived_vrrp_become_master":       prometheus.NewDesc("keepalived_vrrp_become_master", "Became master", labelsVrrp, nil),
		"keepalived_vrrp_release_master":      prometheus.NewDesc("keepalived_vrrp_release_master", "Released master", labelsVrrp, nil),
		"keepalived_vrrp_packet_len_err":      prometheus.NewDesc("keepalived_vrrp_packet_len_err", "Packet length errors", labelsVrrp, nil),
		"keepalived_vrrp_advert_interval_err": prometheus.NewDesc("keepalived_vrrp_advert_interval_err", "Advertisement interval errors", labelsVrrp, nil),
		"keepalived_vrrp_ip_ttl_err":          prometheus.NewDesc("keepalived_vrrp_ip_ttl_err", "TTL errors", labelsVrrp, nil),
		"keepalived_vrrp_invalid_type_rcvd":   prometheus.NewDesc("keepalived_vrrp_invalid_type_rcvd", "Invalid type errors", labelsVrrp, nil),
		"keepalived_vrrp_addr_list_err":       prometheus.NewDesc("keepalived_vrrp_addr_list_err", "Address list errors", labelsVrrp, nil),
		"keepalived_vrrp_invalid_authtype":    prometheus.NewDesc("keepalived_vrrp_invalid_authtype", "Authentication invalid", labelsVrrp, nil),
		"keepalived_vrrp_authtype_mismatch":   prometheus.NewDesc("keepalived_vrrp_authtype_mismatch", "Authentication mismatch", labelsVrrp, nil),
		"keepalived_vrrp_auth_failure":        prometheus.NewDesc("keepalived_vrrp_auth_failure", "Authentication failure", labelsVrrp, nil),
		"keepalived_vrrp_pri_zero_rcvd":       prometheus.NewDesc("keepalived_vrrp_pri_zero_rcvd", "Priority zero received", labelsVrrp, nil),
		"keepalived_vrrp_pri_zero_sent":       prometheus.NewDesc("keepalived_vrrp_pri_zero_sent", "Priority zero sent", labelsVrrp, nil),
	}

	handle, err := libipvs.New()
	if err != nil {
		return coll, err
	}

	labelsLVS := []string{"addr", "proto"}
	metrics["keepalived_lvs_vip_in_packets"] = prometheus.NewDesc("keepalived_lvs_vip_in_packets", "VIP in packets", labelsLVS, nil)
	metrics["keepalived_lvs_vip_out_packets"] = prometheus.NewDesc("keepalived_lvs_vip_out_packets", "VIP out packets", labelsLVS, nil)
	metrics["keepalived_lvs_vip_in_bytes"] = prometheus.NewDesc("keepalived_lvs_vip_in_bytes", "VIP in bytes", labelsLVS, nil)
	metrics["keepalived_lvs_vip_out_bytes"] = prometheus.NewDesc("keepalived_lvs_vip_out_bytes", "VIP out bytes", labelsLVS, nil)
	metrics["keepalived_lvs_vip_conn"] = prometheus.NewDesc("keepalived_lvs_vip_conn", "VIP connections", labelsLVS, nil)
	metrics["keepalived_lvs_rs_in_packets"] = prometheus.NewDesc("keepalived_lvs_rs_in_packets", "RS in packets", labelsLVS, nil)
	metrics["keepalived_lvs_rs_out_packets"] = prometheus.NewDesc("keepalived_lvs_rs_out_packets", "RS out packets", labelsLVS, nil)
	metrics["keepalived_lvs_rs_in_bytes"] = prometheus.NewDesc("keepalived_lvs_rs_in_bytes", "RS in bytes", labelsLVS, nil)
	metrics["keepalived_lvs_rs_out_bytes"] = prometheus.NewDesc("keepalived_lvs_rs_out_bytes", "RS out bytes", labelsLVS, nil)
	metrics["keepalived_lvs_rs_conn"] = prometheus.NewDesc("keepalived_lvs_rs_conn", "RS connections", labelsLVS, nil)

	coll.handle = handle
	coll.metrics = metrics

	return coll, nil
}

// Describe outputs metrics descriptions.
func (k *KACollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range k.metrics {
		ch <- m
	}
}

// Collect fetches metrics from and sends them to the provided channel.
func (k *KACollector) Collect(ch chan<- prometheus.Metric) {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	err := k.signal()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 0)
		log.Printf("keepalived_exporter: %v", err)
		return
	}

	stats := make([]KAStats, 0)

	f, err := os.Open("/tmp/keepalived.json")
	if err != nil {
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 0)
		log.Printf("keepalived_exporter: %v", err)
		return
	}

	decoder := json.NewDecoder(f)

	err = decoder.Decode(&stats)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 0)
		log.Printf("keepalived_exporter: %v", err)
		return
	}

	ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 1)

	for _, st := range stats {
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_advert_rcvd"], prometheus.CounterValue,
			float64(st.Stats.AdvertRcvd), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_advert_sent"], prometheus.CounterValue,
			float64(st.Stats.AdvertSent), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_become_master"], prometheus.CounterValue,
			float64(st.Stats.BecomeMaster), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_release_master"], prometheus.CounterValue,
			float64(st.Stats.ReleaseMaster), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_packet_len_err"], prometheus.CounterValue,
			float64(st.Stats.PacketLenErr), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_advert_interval_err"], prometheus.CounterValue,
			float64(st.Stats.AdvertIntervalErr), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_ip_ttl_err"], prometheus.CounterValue,
			float64(st.Stats.AdvertIntervalErr), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_invalid_type_rcvd"], prometheus.CounterValue,
			float64(st.Stats.InvalidTypeRcvd), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_addr_list_err"], prometheus.CounterValue,
			float64(st.Stats.AddrListErr), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_invalid_authtype"], prometheus.CounterValue,
			float64(st.Stats.InvalidAuthtype), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_authtype_mismatch"], prometheus.CounterValue,
			float64(st.Stats.AuthtypeMismatch), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_auth_failure"], prometheus.CounterValue,
			float64(st.Stats.AuthFailure), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_pri_zero_rcvd"], prometheus.CounterValue,
			float64(st.Stats.PriZeroRcvd), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_pri_zero_sent"], prometheus.CounterValue,
			float64(st.Stats.PriZeroSent), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid))
	}

	svcs, err := k.handle.ListServices()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 0)
		log.Printf("keepalived_exporter: %v", err)
		return
	}

	for _, s := range svcs {
		dsts, err := k.handle.ListDestinations(s)
		if err != nil {
			log.Printf("keepalived_exporter: %v", err)
			continue
		}

		addr := s.Address.String() + ":" + strconv.Itoa(int(s.Port))

		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_vip_in_packets"], prometheus.CounterValue,
			float64(s.Stats.PacketsIn), addr, s.Protocol.String())
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_vip_out_packets"], prometheus.CounterValue,
			float64(s.Stats.PacketsOut), addr, s.Protocol.String())
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_vip_in_bytes"], prometheus.CounterValue,
			float64(s.Stats.BytesIn), addr, s.Protocol.String())
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_vip_out_bytes"], prometheus.CounterValue,
			float64(s.Stats.BytesOut), addr, s.Protocol.String())
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_vip_conn"], prometheus.CounterValue,
			float64(s.Stats.Connections), addr, s.Protocol.String())

		for _, d := range dsts {
			addr := d.Address.String() + ":" + strconv.Itoa(int(d.Port))

			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_rs_in_packets"], prometheus.CounterValue,
				float64(d.Stats.PacketsIn), addr, s.Protocol.String())
			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_rs_out_packets"], prometheus.CounterValue,
				float64(d.Stats.PacketsOut), addr, s.Protocol.String())
			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_rs_in_bytes"], prometheus.CounterValue,
				float64(d.Stats.BytesIn), addr, s.Protocol.String())
			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_rs_out_bytes"], prometheus.CounterValue,
				float64(d.Stats.BytesOut), addr, s.Protocol.String())
			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_rs_conn"], prometheus.CounterValue,
				float64(d.Stats.Connections), addr, s.Protocol.String())
		}
	}
}

// signal sends `SIGJSON` signal to keepalived process.
func (k *KACollector) signal() error {
	ps, err := process.Processes()
	if err != nil {
		return err
	}

	var pid int32
	for _, p := range ps {
		name, err := p.Name()
		if err != nil {
			return err
		}

		if name == "keepalived" {
			pid = p.Pid
			break
		}
	}

	if pid == 0 {
		return errors.New("cannot find pid")
	}

	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}

	err = proc.Signal(SIGJSON)
	if err != nil {
		return err
	}

	time.Sleep(10 * time.Millisecond)
	return nil
}
