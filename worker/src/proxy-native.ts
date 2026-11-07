import { copy, empty, fields, requireConsumed, string, take, unsupported, type Fields } from "./proxy-input.ts";
import { validatedNativeSingBox } from "./singbox-export.ts";

const UDP_TOGGLE = new Set(["shadowsocks", "vmess", "vless", "trojan", "socks", "anytls"]);

export function portableNativeSource(input: Fields, protocol: string): Fields {
  const { output } = validatedNativeSingBox(input, protocol);
  const source = fields(output);
  const result: Fields = { server: take(source, "server"), port: take(source, "server_port") };
  delete source.type;
  copy(source, result, {
    server_ports: "ports", uuid: "uuid", method: "cipher", security: "cipher", alter_id: "alterId",
    global_padding: "global-padding", authenticated_length: "authenticated-length", flow: "flow",
    username: "username", password: "password", plugin: "plugin", plugin_opts: "plugin-opts",
    tcp_fast_open: "tfo", tcp_multi_path: "mptcp", auth: "auth", auth_str: "auth-str",
    congestion_control: "congestion-controller", udp_relay_mode: "udp-relay-mode",
    zero_rtt_handshake: "reduce-rtt", bbr_profile: "bbr-profile",
  });
  if (protocol === "vmess" && result.cipher === "") result.cipher = "auto";
  if (protocol === "socks" && !["", "5", undefined].includes(take(source, "version") as string | undefined)) unsupported();
  const network = take(source, "network");
  if (UDP_TOGGLE.has(protocol)) {
    const networks = Array.isArray(network) ? network : empty(network) ? [] : [network];
    if (networks.length > 0 && !networks.includes("tcp")) unsupported();
    result.udp = networks.length === 0 || networks.includes("udp");
  } else if (!empty(network) && !(Array.isArray(network) && network.includes("tcp") && network.includes("udp"))) unsupported();
  const packetEncoding = take(source, "packet_encoding");
  if (protocol === "vless" && packetEncoding === "" && result.udp) unsupported();
  if (!empty(packetEncoding)) result["packet-encoding"] = packetEncoding;
  const uot = take(source, "udp_over_tcp");
  if (!empty(uot)) {
    if (protocol !== "shadowsocks") unsupported();
    const opts: Fields = typeof uot === "boolean" ? { enabled: uot } : fields(uot);
    result["udp-over-tcp"] = opts.enabled === true;
    if (opts.enabled === true) result["udp-over-tcp-version"] = opts.version === undefined || opts.version === 0 ? 2 : opts.version;
  }
  const tls = take(source, "tls");
  if (!empty(tls)) {
    const opts = fields(tls);
    result.tls = take(opts, "enabled", false);
    copy(opts, result, { server_name: "sni", insecure: "skip-cert-verify", alpn: "alpn", disable_sni: "disable-sni" });
    const utls = take(opts, "utls");
    if (!empty(utls)) {
      const settings = fields(utls);
      if (take(settings, "enabled", false) === true) result["client-fingerprint"] = take(settings, "fingerprint", "chrome");
      requireConsumed(settings);
    }
    const reality = take(opts, "reality");
    if (!empty(reality)) {
      const settings = fields(reality);
      if (take(settings, "enabled", false) === true) {
        const converted: Fields = {};
        copy(settings, converted, { public_key: "public-key", short_id: "short-id" });
        result["reality-opts"] = converted;
      }
      requireConsumed(settings);
    }
    requireConsumed(opts);
  }
  const transport = take(source, "transport");
  if (!empty(transport)) {
    const opts = fields(transport);
    const kind = take(opts, "type");
    if (kind !== "ws" && kind !== "grpc") unsupported();
    result.network = kind;
    const converted: Fields = {};
    copy(opts, converted, {
      path: "path", headers: "headers", max_early_data: "max-early-data", early_data_header_name: "early-data-header-name",
      service_name: "grpc-service-name",
    });
    if (kind === "ws" && result.tls === true && (protocol === "vmess" || protocol === "vless") && empty(result.sni)) {
      result.sni = result.server;
    }
    requireConsumed(opts);
    result[kind + "-opts"] = converted;
  }
  if (protocol === "hysteria" || protocol === "hysteria2") {
    for (const key of ["up", "down"]) {
      const rate = take(source, key);
      const mbps = take(source, key + "_mbps");
      if (rate !== undefined && mbps !== undefined) unsupported();
      result[key] = rate ?? mbps;
    }
    const hop = take(source, "hop_interval");
    if (!empty(hop)) {
      const match = /^([0-9]+)s(?![\s\S])/u.exec(string(hop));
      if (!match) return unsupported();
      result["hop-interval"] = match[1];
    }
    const obfs = take(source, "obfs");
    if (protocol === "hysteria") result.obfs = obfs;
    else if (!empty(obfs)) {
      const opts = fields(obfs);
      copy(opts, result, { type: "obfs", password: "obfs-password", min_packet_size: "obfs-min-packet-size", max_packet_size: "obfs-max-packet-size" });
      requireConsumed(opts);
    }
  }
  requireConsumed(source);
  return result;
}
