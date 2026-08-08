# `tailscale status --json` → Prometheus textfile 格式。
#
# 覆盖 tailnet 里**所有** peer,用 kind 标签分成两类:
#
#   kind="server"  纳管的那几台。缺席是故障。
#   kind="device"  手机、别人的笔记本这些。缺席是常态。
#
# 两类的使用模式完全相反,所以指标里必须能分开 —— 告警只看 server,
# 设备看板只看 device。
#
# ---------------------------------------------------------------------------
# 字段语义,踩过才知道的两条:
#
# 1. **`.Relay` 不是"正在走中继"。** 它是这个 peer 的归属 DERP region,直连
#    状态下照样有值。实测 r6s 走 IPv6 直连(CurAddr = [240e:...]:41641)时
#    .Relay 仍然是 "h610"。拿它当降级判据的话告警会永远为真。
#    这里把它单独导成 tailscale_peer_home_derp,名字说清楚它是什么。
#
# 2. **`.CurAddr` 只在 `.Active == true` 时有意义。** 链路空闲时 CurAddr 是
#    空串、LastHandshake 是零值 —— 那是"不知道",不是"在走中继"。所以
#    direct/relay 这两个指标只在 Active 时输出;空闲的 pair 在 Prometheus 里
#    表现为序列缺失,而不是一个错误的 0。
#
#    对 server 这不是问题:ping_exporter 每 5 秒打一轮,所有 pair 会一直是
#    active。对 device 就是常态了 —— 手机大部分时间既不在线也不 active。
#
# 输出必须**按指标名分组**,不能按 peer 分组:Prometheus 文本格式要求同名
# 指标的样本连续出现,否则 promtool 报 "metric not unique",textfile 采集器
# 会整个文件丢弃。
# ---------------------------------------------------------------------------

def q: tostring | gsub("\\\\"; "\\\\") | gsub("\""; "\\\"");

# UserID → 登录名。tailnet 里二十来台终端设备分属四个人,不带这个标签的话
# 看板上只有一堆 hostname,分不清是谁的。
def userof($users): . as $id | ($users[$id | tostring].LoginName // "unknown");

# LastHandshake 是 RFC3339。三个坑,一个一个踩过来的:
#
#   1. 可能带小数秒("...:14.391193023+08:00"),fromdateiso8601 不接受。
#   2. 可能是 "0001-01-01T00:00:00Z",表示从没握过手 —— 不是时间,是哨兵值。
#   3. **jq 的 mktime 会直接丢掉时区偏移。** `strptime("...%z")|mktime` 和
#      "把偏移当成 Z" 得到的是同一个数,而那个数比真值大了整整一个偏移量
#      (这台是 +08:00,差 28800 秒)。这种错误不会报任何异常,只会让指标
#      静默偏移 8 小时。
#
# 所以偏移必须自己算再减掉。
def handshake:
  (. // "")
  | sub("\\.[0-9]+"; "")
  | if . == "" or startswith("0001-") then 0
    else . as $s
      | ($s | sub("(Z|[+-][0-9]{2}:[0-9]{2})$"; "") + "Z"
             | try fromdateiso8601 catch 0) as $naive
      | if $naive == 0 then 0
        else $naive -
          ( ($s | capture("(?<sign>[+-])(?<h>[0-9]{2}):(?<m>[0-9]{2})$") // null)
            | if . == null then 0
              else ((.h|tonumber)*3600 + (.m|tonumber)*60)
                   * (if .sign=="+" then 1 else -1 end)
              end )
        end
    end;

(.User // {}) as $users
| [
    (.Peer // {}) | to_entries[] | .value
    | select((.DNSName // "") != "")
  ]
| sort_by(.DNSName)
| map(
    # **用 DNSName 的首段,不是 HostName。**
    #
    # HostName 在 tailnet 里不唯一 —— 实测这里有五台 iOS 设备全都自报
    # "localhost"(mtf / marble / lgm / a19pro / m1)。拿它当标签会产生
    # 重复的时序,promtool 报 "metric not unique",整个 .prom 文件被
    # textfile 采集器丢弃 —— 也就是所有路径指标一起消失,而不只是这几台。
    #
    # DNSName 是 headscale 分配的,保证唯一,而且正是 `tailscale status`
    # 第二列显示的那个名字,和 host registry 里的名字对得上(tank →
    # tank.inner.imdomestic.com)。server 侧因此和 ping_exporter 那边
    # relabel 出来的 peer 标签一致,`and on(instance, peer)` 的连接才成立。
    (.DNSName | split(".")[0]) as $hn
  | {
      labels: "peer=\"\($hn | q)\",kind=\"\(if ($servers | index($hn)) != null then "server" else "device" end)\",os=\"\((.OS // "unknown") | q)\",user=\"\((.UserID // 0) | userof($users) | q)\"",
      region: ((.Relay // "") | q),
      online: (if (.Online // false) then 1 else 0 end),
      active: (if (.Active // false) then 1 else 0 end),
      direct: (if ((.CurAddr // "") != "") then 1 else 0 end),
      handshake: (.LastHandshake | handshake),
      rx: (.RxBytes // 0),
      tx: (.TxBytes // 0)
    }
  )
| . as $rows
| (
    [
      "# HELP tailscale_peer_online Peer is online according to the local tailscaled (1) or not (0).",
      "# TYPE tailscale_peer_online gauge"
    ] + ($rows | map("tailscale_peer_online{\(.labels)} \(.online)"))

  + [
      "# HELP tailscale_peer_active A live session exists with this peer; the path metrics are only meaningful when this is 1.",
      "# TYPE tailscale_peer_active gauge"
    ] + ($rows | map("tailscale_peer_active{\(.labels)} \(.active)"))

  + [
      "# HELP tailscale_peer_home_derp The peer's home DERP region. This is NOT evidence of relaying.",
      "# TYPE tailscale_peer_home_derp gauge"
    ] + ($rows | map("tailscale_peer_home_derp{\(.labels),region=\"\(.region)\"} 1"))

  + [
      "# HELP tailscale_peer_last_handshake_timestamp_seconds Unix time of the last wireguard handshake, 0 if never.",
      "# TYPE tailscale_peer_last_handshake_timestamp_seconds gauge"
    ] + ($rows | map("tailscale_peer_last_handshake_timestamp_seconds{\(.labels)} \(.handshake)"))

  + [
      "# HELP tailscale_peer_rx_bytes Bytes received from this peer since tailscaled started.",
      "# TYPE tailscale_peer_rx_bytes gauge"
    ] + ($rows | map("tailscale_peer_rx_bytes{\(.labels)} \(.rx)"))

  + [
      "# HELP tailscale_peer_tx_bytes Bytes sent to this peer since tailscaled started.",
      "# TYPE tailscale_peer_tx_bytes gauge"
    ] + ($rows | map("tailscale_peer_tx_bytes{\(.labels)} \(.tx)"))

    # 下面两个只在 active 时输出,理由见文件头第 2 条。
  + [
      "# HELP tailscale_peer_direct Path is direct (1) or DERP-relayed (0). Only emitted while the session is active.",
      "# TYPE tailscale_peer_direct gauge"
    ] + ($rows | map(select(.active == 1) | "tailscale_peer_direct{\(.labels)} \(.direct)"))

  + [
      "# HELP tailscale_peer_relay Emitted as 1 only when actually relaying; region is the DERP region carrying the traffic.",
      "# TYPE tailscale_peer_relay gauge"
    ] + ($rows | map(select(.active == 1 and .direct == 0) | "tailscale_peer_relay{\(.labels),region=\"\(.region)\"} 1"))
  )
| .[]
