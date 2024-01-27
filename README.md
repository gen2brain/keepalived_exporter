# Keepalived Prometheus Exporter

Prometheus exporter for [Keepalived](https://keepalived.org) metrics.

### Installation

    go get -u github.com/gen2brain/keepalived_exporter

### Usage

| Name               | Description                                                                |
|--------------------|----------------------------------------------------------------------------|
| web.listen-address | Address to listen on for web interface and telemetry, defaults to `:9650`. |
| web.telemetry-path | Path under which to expose metrics, defaults to `/metrics`.                |
| version            | Display version information.                                               |

**Note:** Requirement is to have Keepalived compiled with `--enable-json` configure option.

### Metrics

| Counters                            | Notes                         |
|-------------------------------------|-------------------------------|
| keepalived_vrrp_advert_rcvd         | Advertisements received       |
| keepalived_vrrp_advert_sent         | Advertisements sent           |
| keepalived_vrrp_become_master       | Became master                 |
| keepalived_vrrp_release_master      | Released master               |
| keepalived_vrrp_packet_len_err      | Packet length errors          |
| keepalived_vrrp_advert_interval_err | Advertisement interval errors |
| keepalived_vrrp_ip_ttl_err          | TTL errors                    |
| keepalived_vrrp_invalid_type_rcvd   | Invalid type errors           |
| keepalived_vrrp_addr_list_err       | Address list errors           |
| keepalived_vrrp_invalid_authtype    | Authentication invalid        |
| keepalived_vrrp_authtype_mismatch   | Authentication mismatch       |
| keepalived_vrrp_auth_failure        | Authentication failure        |
| keepalived_vrrp_pri_zero_rcvd       | Priority zero received        |
| keepalived_vrrp_pri_zero_sent       | Priority zero sent            |
| keepalived_lvs_vip_in_packets       | VIP in packets                |
| keepalived_lvs_vip_out_packets      | VIP out packets               |
| keepalived_lvs_vip_in_bytes         | VIP in bytes                  |
| keepalived_lvs_vip_out_bytes        | VIP out bytes                 |
| keepalived_lvs_vip_conn             | VIP connections               |
| keepalived_lvs_rs_in_packets        | RS in packets                 |
| keepalived_lvs_rs_out_packets       | RS out packets                |
| keepalived_lvs_rs_in_bytes          | RS in bytes                   |
| keepalived_lvs_rs_out_bytes         | RS out bytes                  |
| keepalived_lvs_rs_conn              | RS connections                |
