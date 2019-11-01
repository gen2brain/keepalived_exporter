package collector

import (
	"bufio"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/libnetwork/ipvs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/process"
)

// Signals.
const (
	SIGRTMIN = syscall.Signal(32)
	SIGJSON  = syscall.Signal(SIGRTMIN + 4)
)

// States.
const (
	Init = iota
	Backup
	Master
	Fault
)

// States map.
var string2state = map[string]int{
	"INIT":   Init,
	"BACKUP": Backup,
	"MASTER": Master,
	"FAULT":  Fault,
}

// States map.
var state2string = map[int]string{
	Init:   "INIT",
	Backup: "BACKUP",
	Master: "MASTER",
	Fault:  "FAULT",
}

// KAStats type.
type KAStats struct {
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

// KACollector type.
type KACollector struct {
	useJSON bool
	metrics map[string]*prometheus.Desc
	handle  *ipvs.Handle
	mutex   sync.Mutex
}

// NewKACollector creates an KACollector.
func NewKACollector(useJSON bool) (*KACollector, error) {
	coll := &KACollector{}
	coll.useJSON = useJSON

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

		coll.handle = handle
	}

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

	var err error
	var kaStats []KAStats

	if k.useJSON {
		kaStats, err = k.json()
		if err != nil {
			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 0)
			log.Printf("keepalived_exporter: %v", err)
			return
		}
	} else {
		kaStats, err = k.text()
		if err != nil {
			ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 0)
			log.Printf("keepalived_exporter: %v", err)
			return
		}
	}

	ch <- prometheus.MustNewConstMetric(k.metrics["keepalived_up"], prometheus.GaugeValue, 1)

	for _, st := range kaStats {
		state := ""
		if _, ok := state2string[st.Data.State]; ok {
			state = state2string[st.Data.State]
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
		log.Printf("keepalived_exporter: %v", err)
		return
	}

	for _, s := range svcs {
		dsts, err := k.handle.GetDestinations(s)
		if err != nil {
			log.Printf("keepalived_exporter: %v", err)
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
func (k *KACollector) signal(sig syscall.Signal) error {
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

	err = proc.Signal(sig)
	if err != nil {
		return err
	}

	time.Sleep(10 * time.Millisecond)
	return nil
}

// json returns slice of KAStats from json file.
func (k *KACollector) json() ([]KAStats, error) {
	kaStats := make([]KAStats, 0)

	err := k.signal(SIGJSON)
	if err != nil {
		return kaStats, err
	}

	return k.decodeJson()
}

// text returns slice of KAStats from text files.
func (k *KACollector) text() ([]KAStats, error) {
	kaStats := make([]KAStats, 0)

	err := k.signal(syscall.SIGUSR1)
	if err != nil {
		return kaStats, err
	}

	err = k.signal(syscall.SIGUSR2)
	if err != nil {
		return kaStats, err
	}

	data, err := k.parseData()
	if err != nil {
		return kaStats, err
	}

	stats, err := k.parseStats()
	if err != nil {
		return kaStats, err
	}

	if len(data) == len(stats) {
		for idx, _ := range data {
			st := KAStats{}
			st.Data = data[idx]
			st.Stats = stats[idx]
			kaStats = append(kaStats, st)
		}
	}

	return kaStats, nil
}

// decodeJson decodes stats from json file.
func (k *KACollector) decodeJson() ([]KAStats, error) {
	stats := make([]KAStats, 0)

	f, err := os.Open("/tmp/keepalived.json")
	if err != nil {
		return stats, err
	}

	defer f.Close()

	decoder := json.NewDecoder(f)

	err = decoder.Decode(&stats)
	if err != nil {
		return stats, err
	}

	return stats, nil
}

// parseData decodes data from text file.
func (k *KACollector) parseData() ([]Data, error) {
	data := make([]Data, 0)

	f, err := os.Open("/tmp/keepalived.data")
	if err != nil {
		return data, err
	}

	defer f.Close()

	sep := "VRRP Instance"
	prop := "="

	dt := Data{}
	scanner := bufio.NewScanner(bufio.NewReader(f))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " "+sep) && strings.Contains(line, prop) {
			sp := strings.Split(strings.TrimSpace(line), prop)
			dt.Iname = strings.TrimSpace(sp[1])
		} else if strings.HasPrefix(line, "   ") && strings.Contains(line, prop) && dt.Iname != "" {
			sp := strings.Split(strings.TrimSpace(line), prop)
			key := strings.TrimSpace(sp[0])
			val := strings.TrimSpace(sp[1])
			switch key {
			case "Interface":
				dt.IfpIfname = val
			case "Last transition":
				lt, err := strconv.ParseFloat(strings.Split(val, " ")[0], 64)
				if err != nil {
					return data, err
				}

				dt.LastTransition = lt
			case "Virtual Router ID":
				id, err := strconv.Atoi(val)
				if err != nil {
					return data, err
				}

				dt.Vrid = id
			case "State":
				if state, ok := string2state[val]; ok {
					dt.State = state
				}
			case "Wantstate":
				if state, ok := string2state[val]; ok {
					dt.Wantstate = state
				}
			}
		} else {
			if dt.Iname != "" {
				data = append(data, dt)
				dt = Data{}
			}
		}
	}

	return data, nil
}

// parseStats decodes stats from text file.
func (k *KACollector) parseStats() ([]Stats, error) {
	data := make([]Stats, 0)

	f, err := os.Open("/tmp/keepalived.stats")
	if err != nil {
		return data, err
	}

	defer f.Close()

	sep := "VRRP Instance"
	prop := ":"

	dt := Stats{}
	scanner := bufio.NewScanner(bufio.NewReader(f))

	section := ""
	instance := ""

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, sep) && strings.Contains(line, prop) {
			if instance != "" {
				data = append(data, dt)
				dt = Stats{}
				instance = ""
			}

			sp := strings.Split(strings.TrimSpace(line), prop)
			instance = strings.TrimSpace(sp[1])
		} else if strings.HasPrefix(line, "  ") && strings.HasSuffix(line, prop) {
			sp := strings.Split(strings.TrimSpace(line), prop)
			section = strings.TrimSpace(sp[0])
		} else if strings.HasPrefix(line, "    ") && section != "" {
			sp := strings.Split(strings.TrimSpace(line), prop)
			key := strings.TrimSpace(sp[0])
			val := strings.TrimSpace(sp[1])

			value, err := strconv.Atoi(val)
			if err != nil {
				return data, err
			}

			switch section {
			case "Advertisements":
				switch key {
				case "Received":
					dt.AdvertRcvd = value
				case "Sent":
					dt.AdvertSent = value
				}
			case "Packet Errors":
				switch key {
				case "Length":
					dt.PacketLenErr = value
				case "TTL":
					dt.IPTTLErr = value
				case "Invalid Type":
					dt.InvalidTypeRcvd = value
				case "Advertisement Interval":
					dt.AdvertIntervalErr = value
				case "Address List":
					dt.AddrListErr = value
				}
			case "Authentication Errors":
				switch key {
				case "Invalid Type":
					dt.InvalidAuthtype = value
				case "Type Mismatch":
					dt.AuthtypeMismatch = value
				case "Failure":
					dt.AuthFailure = value
				}
			case "Priority Zero":
				switch key {
				case "Received":
					dt.PriZeroRcvd = value
				case "Sent":
					dt.PriZeroSent = value
				}
			}
		} else if strings.HasPrefix(line, "  ") && !strings.HasSuffix(line, prop) && !strings.HasPrefix(line, "    ") {
			sp := strings.Split(strings.TrimSpace(line), prop)
			key := strings.TrimSpace(sp[0])
			val := strings.TrimSpace(sp[1])
			section = ""

			value, err := strconv.Atoi(val)
			if err != nil {
				return data, err
			}

			switch key {
			case "Became master":
				dt.BecomeMaster = value
			case "Released master":
				dt.ReleaseMaster = value
			}
		}
	}

	if instance != "" {
		data = append(data, dt)
	}

	return data, nil
}
