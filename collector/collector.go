package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/moby/ipvs"
	"github.com/prometheus/client_golang/prometheus"
)

// Signals.
const (
	SIGRTMIN = syscall.Signal(32)
	SIGJSON  = SIGRTMIN + 4
)

// States.
const (
	Init = iota
	Backup
	Master
	Fault
)

// States map.
var states = map[int]string{
	Init:   "INIT",
	Backup: "BACKUP",
	Master: "MASTER",
	Fault:  "FAULT",
}

// KA type.
type KA struct {
	Data  Data  `json:"data"`
	Stats Stats `json:"stats"`
}

// Data type.
type Data struct {
	Iname          string  `json:"iname"`
	IfpIfname      string  `json:"ifp_ifname"`
	LastTransition float64 `json:"last_transition"`
	Vrid           int     `json:"vrid"`
	State          int     `json:"state"`
	Wantstate      int     `json:"wantstate"`
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

// Collector type.
type Collector struct {
	metrics map[string]*prometheus.Desc
	handle  *ipvs.Handle
	mutex   sync.Mutex
}

// NewCollector creates a Collector.
func NewCollector() (*Collector, error) {
	c := &Collector{}

	labelsVrrp := []string{"name", "intf", "vrid", "state"}

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

	c.metrics = metrics

	if handle, err := ipvs.New(""); err == nil {
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

		c.handle = handle
	}

	return c, nil
}

// Describe outputs metrics descriptions.
func (k *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range k.metrics {
		ch <- m
	}
}

// Collect fetches metrics from and sends them to the provided channel.
func (k *Collector) Collect(ch chan<- prometheus.Metric) {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	ka, err := k.decode()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 0)
		log.Printf("keepalived_exporter: %v", err)
		return
	}

	ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 1)

	for _, st := range ka {
		var state string
		if _, ok := states[st.Data.State]; ok {
			state = states[st.Data.State]
		}

		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_advert_rcvd"], prometheus.CounterValue,
			float64(st.Stats.AdvertRcvd), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_advert_sent"], prometheus.CounterValue,
			float64(st.Stats.AdvertSent), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_become_master"], prometheus.CounterValue,
			float64(st.Stats.BecomeMaster), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_release_master"], prometheus.CounterValue,
			float64(st.Stats.ReleaseMaster), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_packet_len_err"], prometheus.CounterValue,
			float64(st.Stats.PacketLenErr), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_advert_interval_err"], prometheus.CounterValue,
			float64(st.Stats.AdvertIntervalErr), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_ip_ttl_err"], prometheus.CounterValue,
			float64(st.Stats.AdvertIntervalErr), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_invalid_type_rcvd"], prometheus.CounterValue,
			float64(st.Stats.InvalidTypeRcvd), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_addr_list_err"], prometheus.CounterValue,
			float64(st.Stats.AddrListErr), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_invalid_authtype"], prometheus.CounterValue,
			float64(st.Stats.InvalidAuthtype), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_authtype_mismatch"], prometheus.CounterValue,
			float64(st.Stats.AuthtypeMismatch), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_auth_failure"], prometheus.CounterValue,
			float64(st.Stats.AuthFailure), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_pri_zero_rcvd"], prometheus.CounterValue,
			float64(st.Stats.PriZeroRcvd), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_vrrp_pri_zero_sent"], prometheus.CounterValue,
			float64(st.Stats.PriZeroSent), st.Data.Iname, st.Data.IfpIfname, strconv.Itoa(st.Data.Vrid), state)
	}

	if k.handle == nil {
		return
	}

	svcs, err := k.handle.GetServices()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 0)
		log.Printf("keepalived_exporter: services: %v", err)
		return
	}

	for _, s := range svcs {
		dsts, err := k.handle.GetDestinations(s)
		if err != nil {
			log.Printf("keepalived_exporter: destinations: %v", err)
			continue
		}

		addr := s.Address.String() + ":" + strconv.Itoa(int(s.Port))
		proto := strconv.Itoa(int(s.Protocol))

		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_vip_in_packets"], prometheus.CounterValue,
			float64(s.Stats.PacketsIn), addr, proto)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_vip_out_packets"], prometheus.CounterValue,
			float64(s.Stats.PacketsOut), addr, proto)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_vip_in_bytes"], prometheus.CounterValue,
			float64(s.Stats.BytesIn), addr, proto)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_vip_out_bytes"], prometheus.CounterValue,
			float64(s.Stats.BytesOut), addr, proto)
		ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_vip_conn"], prometheus.CounterValue,
			float64(s.Stats.Connections), addr, proto)

		for _, d := range dsts {
			addr := d.Address.String() + ":" + strconv.Itoa(int(d.Port))

			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_rs_in_packets"], prometheus.CounterValue,
				float64(d.Stats.PacketsIn), addr, proto)
			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_rs_out_packets"], prometheus.CounterValue,
				float64(d.Stats.PacketsOut), addr, proto)
			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_rs_in_bytes"], prometheus.CounterValue,
				float64(d.Stats.BytesIn), addr, proto)
			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_rs_out_bytes"], prometheus.CounterValue,
				float64(d.Stats.BytesOut), addr, proto)
			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_lvs_rs_conn"], prometheus.CounterValue,
				float64(d.Stats.Connections), addr, proto)
		}
	}
}

// signal sends given signal to keepalived process.
func (k *Collector) signal(sig syscall.Signal) error {
	ps, err := processes()
	if err != nil {
		return err
	}

	var pid int64
	for _, p := range ps {
		if p[1] == "keepalived" {
			pid, err = strconv.ParseInt(p[0], 10, 0)
			if err != nil {
				return err
			}

			break
		}
	}

	if pid == 0 {
		return fmt.Errorf("cannot find pid")
	}

	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("cannot find process for pid %d: %w", pid, err)
	}

	err = proc.Signal(sig)
	if err != nil {
		return fmt.Errorf("cannot send signal %v: %w", sig, err)
	}

	time.Sleep(100 * time.Millisecond)

	return nil
}

// decode decodes stats from json file.
func (k *Collector) decode() ([]KA, error) {
	ka := make([]KA, 0)

	err := k.signal(SIGJSON)
	if err != nil {
		return ka, err
	}

	f, err := os.Open("/tmp/keepalived.json")
	if err != nil {
		return ka, err
	}
	defer f.Close()

	defer func() {
		files, err := filepath.Glob("/tmp/keepalived.json*")
		if err == nil {
			for _, file := range files {
				if file != "/tmp/keepalived.json" {
					_ = os.Remove(file)
				}
			}
		}
	}()

	err = json.NewDecoder(f).Decode(&ka)
	if err != nil {
		return ka, err
	}

	return ka, nil
}

// processes returns slice of process fields(pid, comm, pcpu, pmem) from ps command.
func processes() ([][]string, error) {
	ret := make([][]string, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, "ps", "-axwwo", "pid,pcpu,pmem,args").CombinedOutput()
	if err != nil {
		return ret, err
	}

	// remove trailing newline and header
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")[1:]

	for _, line := range lines {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) > 3 {
			comm := f[3]
			if !strings.HasPrefix(comm, "[") {
				comm = filepath.Base(comm)
			}
			ret = append(ret, []string{f[0], comm, f[1], f[2]})
		}
	}

	return ret, nil
}
