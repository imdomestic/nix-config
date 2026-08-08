# `tailscale status --json` → Prometheus textfile 格式。
#
# 只输出 $peers 里的机器(纳管的那几台)。tailnet 里还挂着十几台手机和笔记本,
# 它们本来就大部分时间离线,混进来只会让指标变噪声。
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
#    实践中这不是问题:ping_exporter 每 5 秒打一轮,所有 pair 会一直是 active。
#    两层是互相成就的 —— ping 提供延迟数字,顺便把路径探测保持在有效状态。
# ---------------------------------------------------------------------------

def q: tostring | gsub("\\\\"; "\\\\") | gsub("\""; "\\\"");

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

[
  "# HELP tailscale_peer_online Peer is online according to the local tailscaled (1) or not (0).",
  "# TYPE tailscale_peer_online gauge",
  "# HELP tailscale_peer_active A live session exists with this peer; the path metrics below are only meaningful when this is 1.",
  "# TYPE tailscale_peer_active gauge",
  "# HELP tailscale_peer_direct Path is direct (1) or DERP-relayed (0). Only emitted while the session is active.",
  "# TYPE tailscale_peer_direct gauge",
  "# HELP tailscale_peer_relay Emitted as 1 only when actually relaying; region is the DERP region carrying the traffic.",
  "# TYPE tailscale_peer_relay gauge",
  "# HELP tailscale_peer_home_derp The peer's home DERP region. This is NOT evidence of relaying.",
  "# TYPE tailscale_peer_home_derp gauge",
  "# HELP tailscale_peer_last_handshake_timestamp_seconds Unix time of the last wireguard handshake, 0 if never.",
  "# TYPE tailscale_peer_last_handshake_timestamp_seconds gauge"
]
+ (
  [
    (.Peer // {}) | to_entries[] | .value
    | select((.HostName // "") as $h | ($peers | index($h)) != null)
  ]
  | sort_by(.HostName)
  | map(
      (.HostName | q) as $p
    | ((.Active // false) == true) as $active
    | ((.CurAddr // "") != "") as $direct
    | (
        "tailscale_peer_online{peer=\"\($p)\"} \(if (.Online // false) then 1 else 0 end)",
        "tailscale_peer_active{peer=\"\($p)\"} \(if $active then 1 else 0 end)",
        "tailscale_peer_home_derp{peer=\"\($p)\",region=\"\((.Relay // "") | q)\"} 1",
        "tailscale_peer_last_handshake_timestamp_seconds{peer=\"\($p)\"} \(.LastHandshake | handshake)",

        # 空闲时什么都不输出 —— 见文件头第 2 条。
        (if $active | not then empty
         else "tailscale_peer_direct{peer=\"\($p)\"} \(if $direct then 1 else 0 end)"
         end),
        (if ($active and ($direct | not)) then
           "tailscale_peer_relay{peer=\"\($p)\",region=\"\((.Relay // "") | q)\"} 1"
         else empty
         end)
      )
    )
  | flatten
)
| .[]
