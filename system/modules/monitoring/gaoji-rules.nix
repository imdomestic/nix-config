[
  {
    alert = "GaojiOfficialUnavailable";
    expr = ''gaoji_qq_official_healthy{job="gaoji"} == 0'';
    "for" = "2m";
    labels.severity = "critical";
    annotations = {
      summary = "Gaoji QQ transport is not ready";
      description = "The process may be active, but its account lease, gateway or sender is unavailable. Check /health/qq-official; do not force promotion or replay unknown deliveries.";
    };
  }
  {
    alert = "GaojiOfficialMessageGap";
    expr = ''gaoji_qq_official_message_gap{job="gaoji"} > 0'';
    "for" = "1m";
    labels.severity = "warning";
    annotations = {
      summary = "Gaoji reports a historical QQ message gap";
      description = "Current transport can be ready while messages from an earlier session gap remain missing. Important requests may need resending; restarting only clears the in-memory indicator, not the gap.";
    };
  }
]
