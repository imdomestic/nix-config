# The Rust rewrite of Max, as its own stack: its own user, Postgres
# cluster, directories and units, all named maxx; backed up by
# ./maxx-backup.nix. The Haskell max is gone from tank; its database (in the
# host's cluster) and /var/lib/max stay. Design: the max repo's docs/. It
# reaches QQ through Tencent's official bot API, as the bot maxx.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cliproxy = import ../../lib/cliproxy-models.nix {placement = config.my.fleet.placements.cliproxy;};
  agyPlacement = config.my.fleet.placements.agy-proxy;
  # owners: `qq:<user_openid>` per line, from the private chat's endpoint.
  # github-token: maxxagent's classic token, public_repo only;
  # github-git-auth: base64 of x-access-token:<the same token>, the basic
  # auth git's HTTPS takes. Change both together.
  secretNames = ["qq-app-id" "qq-app-secret" "owners" "github-token" "github-git-auth"];
  secret = name: config.sops.secrets."maxx/${name}".path;
  # Makers' list prices, US$ per million tokens, for the cost /status
  # shows; the public API's even where the model is free to us. Looked up
  # 2026-11-12 on the makers' pricing pages, the rate for short prompts.
  price = input: cached: output: {inherit input cached output;};
  prices = {
    # Promotional until 2026-12-31, then 1.50 / 0.15 / 7.50.
    gemini-flash = price 0.75 0.075 3.75;
    gemini-3-flash = price 0.5 0.05 3;
    gemini-3-1-flash-lite = price 0.25 0.025 1.5;
    gemini-3-5-flash-lite = price 0.3 0.03 2.5;
    # Existing public-API estimate for Argon/Carbon, not the AGY subscription bill.
    gemini-4 = price 2 0.1 10;
    gemini-4-hydrogen = price 1.5 0.075 7.5;
    # As docs/home/pi-model-pricing.md has it, checked 2026-10-18.
    gpt-6-1-sol = price 2 0.1 10;
    # Checked 2026-11-18, as the same file has it.
    gpt-6-2-sol = price 2 0.1 10;
    gpt-6-astra = price 10 1 50;
    # Promotional until 2026-11-30.
    gpt-5-6-sol = price 4 0.4 20;
    gpt-5-6-terra = price 2 0.2 12;
    gpt-5-6-luna = price 0.2 0.02 1.2;
    # DeepSeek's peak rate; off-peak is half.
    deepseek-flash = price 0.3 0.006 1.2;
    mimo-flash = price 0.14 0.0028 0.28;
    # On our own GPUs: no per-token price.
    local = price 0 0 0;
  };
  opencodePrices = {
    "deepseek-v4.1-flash" = prices.deepseek-flash;
    "mimo-v2.6-flash" = prices.mimo-flash;
  };
  googleHydrogen = {
    context_window = 262144;
    video = true;
    price = prices.gemini-4-hydrogen;
  };
  # What `system-deploy` says of a switch that only Max can: see
  # `my.systemDeploy.checks.maxx` below. `maxx-psql` and `maxx-ssh` are the
  # max module's, on the system's path, which system-deploy passes on.
  deployHook = name: text:
    lib.getExe (pkgs.writeShellApplication {
      name = "maxx-deploy-${name}";
      runtimeInputs = [config.nix.package config.systemd.package pkgs.coreutils pkgs.gnugrep pkgs.gawk];
      inherit text;
    });
  migration = ''maxx-psql -XAtc "select coalesce(max(version), 0) from _sqlx_migrations"'';
  deployBefore = deployHook "before" ''
    guest() { nix-store --query --requisites "$1" | grep -- '-max-guest\.json$' | sort | tr '\n' ' ' || true; }
    if [[ $(guest "$1") == "$(guest "$2")" ]]; then
      echo "the guest image stays: a restart of Max leaves the VMs running"
    else
      echo "the guest image changes: the switch stops every VM, with the background commands and agents in it, and each boots the new image when next needed"
    fi
    turns=$(maxx-psql -XAtc "select coalesce(string_agg(distinct t.conversation_id::text, ' '), ''') from turns t where not exists (select 1 from turn_outcomes o where o.turn_id = t.id) and t.started_at > now() - interval '6 hours'" 2>/dev/null) || turns="unknown, the query failed"
    echo "conversations with a turn open, which a restart of Max ends: ''${turns:-none}"
    while read -r vm _; do
      n=''${vm#maxx-vm@}
      n=''${n%.service}
      units=$(timeout 15 maxx-ssh "$n" "systemctl list-units 'max-job-*' 'max-call-*' --state=running,activating --no-legend --plain" 2>/dev/null | awk '{print $1}' | tr '\n' ' ') || units="its VM didn't answer"
      if [[ -n $units ]]; then echo "conversation $n runs: $units"; fi
    done < <(systemctl list-units 'maxx-vm@*' --state=active --no-legend --plain)
  '';
  deployAfter = deployHook "after" ''
    if [[ $1 == "$2" ]]; then
      echo "Max wasn't restarted"
      exit 0
    fi
    log=$(journalctl _SYSTEMD_UNIT=maxx.service _PID="$1" --no-pager --output=cat || true)
    count() { grep -c -- "$1" <<<"$log" || true; }
    echo "$(grep -o 'serving version=.*' <<<"$log" | tail -n 1 || true), on migration $(${migration} 2>/dev/null || echo unknown)"
    echo "$(count 'attached to a VM that runs') VMs attached to, $(count "can't be attached to") stopped for the new image, $(count ' ERROR ') errors logged"
  '';
in {
  sops.secrets =
    lib.genAttrs (map (name: "maxx/${name}") secretNames) (_: {
      sopsFile = ../../secrets/hosts/tank-max.yaml;
      owner = "maxx";
      restartUnits = ["maxx.service"];
    })
    // {
      "maxx/agy-completions-api-key" = {
        sopsFile = ../../secrets/clients/agy-proxy.yaml;
        key = "agy-proxy/api_key";
        owner = "maxx";
        restartUnits = ["maxx.service"];
      };
      # The key the Haskell max had for cliproxy, still under its name.
      "maxx/cliproxy-api-key" = {
        sopsFile = ../../secrets/hosts/tank-max.yaml;
        key = "llm-profiles-gemini-3.8-flash-api-key";
        owner = "maxx";
        restartUnits = ["maxx.service"];
      };
      # web_search's, Exa's: the Haskell max's, under its name.
      "maxx/exa-api-key" = {
        sopsFile = ../../secrets/hosts/tank-max.yaml;
        key = "search-exa-api-key";
        owner = "maxx";
        restartUnits = ["maxx.service"];
      };
      # The Haskell max's Bungie application key, for the read-only
      # forwarder; its OAuth client id and secret stay unused.
      "maxx/bungie-api-key" = {
        sopsFile = ../../secrets/hosts/tank-max.yaml;
        key = "bungie-api-key";
        owner = "maxx";
        restartUnits = ["maxx.service"];
      };
    }
    # The other providers' keys the Haskell max had, under its profiles'
    # names; one profile's for a provider whose profiles share a key.
    // lib.mapAttrs' (name: profile:
      lib.nameValuePair "maxx/${name}-api-key" {
        sopsFile = ../../secrets/hosts/tank-max.yaml;
        key = "llm-profiles-${profile}-api-key";
        owner = "maxx";
        restartUnits = ["maxx.service"];
      }) {
      taipan = "qwen3.8-27b";
      deepseek = "deepseek-v4-flash-vision-exp";
    };

  services.maxx = {
    enable = true;
    # The groups' VMs, where the tools run: 32 at a time, on taps from
    # 10.235.0.0/24.
    vm.enable = true;
    # maxx's own cluster: its database was 1.4 GB in 2026-11, its tables'
    # rows mostly appended and read back by recent ones.
    postgresql.settings.shared_buffers = "1GB";
    settings = {
      # Each VM's size, up from maxx's default of 2 vCPUs and 4 GiB
      # (2026-10-31). Up to 12 chats' VMs stay on for the programs Max
      # keeps in them, up from 4, which were taken (2026-11-03): friends
      # use Max as a personal agent in private chats, and maxx trims idle
      # VMs' caches, so a kept VM that idles stays small.
      vm = {
        cpus = 8;
        memory_mib = 16384;
        kept = 12;
      };
      owners_file = secret "owners";
      llm = {
        default = {
          model = "cliproxy/gemini-3.8-flash-high";
          effort = "high";
        };
        # Qwen 3.5 4B on h610's llama.cpp, which doesn't think (--reasoning
        # off) and answers at once: 3000 tokens of prompt in 7 s, 0.3 s
        # once cached (2026-11-11). OpenCode's DeepSeek V4.1 Flash, which
        # had judged since 11-04, answered 503 auth_unavailable that day.
        intent.model = "h610/qwen3.5-4b-q4_k_m";
        # Says what each new picture and sticker shows; the Haskell max's
        # captioner too.
        caption = {
          model = "cliproxy-responses/gpt-5.6-luna";
          effort = "high";
        };
        # Background agents: pi in the groups' VMs, its model calls
        # forwarded by maxx with the provider's key. This is the model one
        # runs on unless Max starts it on another of those below; until
        # 2026-11-24 it was gpt-6.1-sol, and until 2026-11-13 Rewind's
        # gpt-6-astra, asked for xhigh, which pi sent as high.
        job = {
          model = "cliproxy-responses/gpt-6.2-sol";
          effort = "high";
        };
        # The Haskell max's models that see pictures, for /model; maxx
        # takes every model to see them. A window nobody wrote down is the
        # Haskell max's default, 131072.
        providers = {
          agy-completions = {
            base_url = "https://${agyPlacement.tsName}/agy/v1";
            protocol = "chat";
            api_key_file = secret "agy-completions-api-key";
            retries = 0;
            stream_idle_timeout_secs = 240;
            models =
              lib.mapAttrs (id: model: {
                context_window = cliproxy.gemini.context;
                max_output = model.output;
                price =
                  {
                    "gemini-3-flash" = prices.gemini-3-flash;
                    "gemini-3.1-flash-lite" = prices.gemini-3-1-flash-lite;
                    "gemini-3.5-flash-lite" = prices.gemini-3-5-flash-lite;
                    "gemini-3.8-flash-high" = prices.gemini-flash;
                  }
                  .${
                    id
                  };
              })
              cliproxy.gemini.models
              // lib.genAttrs cliproxy.antigravityHydrogen.ids (_: googleHydrogen // {video = false;})
              // lib.genAttrs (lib.concatMap
                (family: map (level: "gemini-4-${family}-${level}") ["low" "medium" "high"])
                ["argon" "carbon"]) (_: {
                context_window = 262144;
                max_output = 65536;
                price = prices.gemini-4;
              });
          };
          cliproxy = {
            base_url = cliproxy.baseUrl;
            protocol = "chat";
            api_key_file = secret "cliproxy-api-key";
            # Argon thinks without a word for up to ~110 s on calls that
            # then answer; at maxx's default 120 s, 27 calls in two days were
            # cut off and started over (2026-10-31). Flash's longest is ~60 s.
            stream_idle_timeout_secs = 240;
            models =
              {
                # These Gemini endpoints passed max.video's clip test (2026-11-03).
                "gemini-3.8-flash-high" = {
                  context_window = cliproxy.gemini.context;
                  max_output = cliproxy.gemini.models."gemini-3.8-flash-high".output;
                  video = true;
                  price = prices.gemini-flash;
                };
              }
              // lib.genAttrs cliproxy.antigravityHydrogen.ids (_: googleHydrogen)
              // lib.mapAttrs' (id: model:
                lib.nameValuePair "opencode/${id}" ({
                    context_window = model.context;
                    max_output = model.output;
                  }
                  // lib.optionalAttrs (opencodePrices ? ${id}) {price = opencodePrices.${id};}))
              cliproxy.opencode.models;
          };
          # The same cliproxy and key; GPT's reasoning only round-trips
          # through Responses.
          cliproxy-responses = {
            base_url = cliproxy.baseUrl;
            protocol = "responses";
            api_key_file = secret "cliproxy-api-key";
            models = {
              "gpt-6.2-sol" = {
                context_window = cliproxy.gpt.context;
                max_output = cliproxy.gpt.output;
                price = prices.gpt-6-2-sol;
              };
              "gpt-6.1-sol" = {
                context_window = cliproxy.gpt.context;
                max_output = cliproxy.gpt.output;
                price = prices.gpt-6-1-sol;
              };
              "gpt-6-astra" = {
                context_window = cliproxy.gpt.context;
                max_output = cliproxy.gpt.output;
                price = prices.gpt-6-astra;
              };
              "gpt-5.6-sol" = {
                context_window = cliproxy.gpt.context;
                max_output = cliproxy.gpt.output;
                price = prices.gpt-5-6-sol;
              };
              "gpt-5.6-terra" = {
                context_window = cliproxy.gpt.context;
                max_output = cliproxy.gpt.output;
                price = prices.gpt-5-6-terra;
              };
              "gpt-5.6-luna" = {
                context_window = cliproxy.gpt.context;
                max_output = cliproxy.gpt.output;
                price = prices.gpt-5-6-luna;
              };
              # Rewind's, through cliproxy's Rewind plugin.
              "rewind/gpt-6-astra" = {
                context_window = cliproxy.rewind.context;
                max_output = cliproxy.rewind.output;
                price = prices.gpt-6-astra;
              };
            };
          };
          taipan = {
            base_url = "http://taipan.inner.imdomestic.com:8000/v1";
            protocol = "chat";
            api_key_file = secret "taipan-api-key";
            models."qwen3.8-27b" = {
              context_window = 262144;
              price = prices.local;
            };
          };
          deepseek = {
            base_url = "https://api.deepseek.com/v1";
            protocol = "chat";
            api_key_file = secret "deepseek-api-key";
            # Retired: DeepSeek answers it with V4.1 Flash, at Flash's price.
            models."deepseek-v4-flash-vision-exp" = {
              context_window = 131072;
              price = prices.deepseek-flash;
            };
          };
          # Not here, as of 2026-10-29: grok-4.5 (its relay answers 403
          # "Task APIs are private during staging deployment").
          h610 = {
            base_url = "http://h610.inner.imdomestic.com:11435/v1";
            protocol = "chat";
            # llama.cpp's --ctx-size in hosts/h610/qwen35-sycl.nix.
            models."qwen3.5-4b-q4_k_m" = {
              context_window = 32768;
              price = prices.local;
            };
          };
        };
      };
      platforms.qq = {
        app_id_file = secret "qq-app-id";
        app_secret_file = secret "qq-app-secret";
      };
      search.api_key_file = secret "exa-api-key";
      # Max's own GitHub account: its commits in the VMs are by it. Max
      # calls GitHub through the APIs below, and judges for itself what to
      # do there.
      github = {
        login = "maxxagent";
        user_id = 350365311;
      };
      api = {
        github = {
          base_url = "https://api.github.com";
          secret_file = secret "github-token";
          headers = {
            Authorization = "Bearer {secret}";
            Accept = "application/vnd.github+json";
            X-GitHub-Api-Version = "2022-11-28";
            User-Agent = "maxxagent";
          };
          about = "你的 GitHub 账号 maxxagent 的 REST API（token 是 classic 的，只有 public_repo）：读 PR、review、CI，fork（POST /repos/{owner}/{repo}/forks），开 PR（POST /repos/{owner}/{repo}/pulls，head 写 maxxagent:分支），之后改、关、评论。PR 只在群友要你开时开，描述末尾用一行英文说明是 AI 应群友要求开的；GitHub 会封看着像刷屏的账号。";
        };
        github-git = {
          base_url = "https://github.com";
          secret_file = secret "github-git-auth";
          headers.Authorization = "Basic {secret}";
          about = "git 的 HTTPS，带着 maxxagent 的认证：推到你的仓库或 fork 用 git push http://127.0.0.1:7777/api/github-git/maxxagent/仓库.git 分支；clone、fetch 公开仓库直接用 https://github.com。";
        };
        # Public reads only: no player logs in, so nothing private and no
        # moving or equipping items. The two POSTs are searches.
        bungie = {
          base_url = "https://www.bungie.net/Platform";
          secret_file = secret "bungie-api-key";
          headers.X-API-Key = "{secret}";
          allow = [
            "GET /**"
            "POST /Destiny2/SearchDestinyPlayerByBungieName/**"
            "POST /User/Search/GlobalName/**"
          ];
          per_hour = 1000;
          about = "Destiny 2 的 Bungie API，只读公开数据：玩家资料和战绩、活动记录、每周的突袭挑战、商人。文档 https://bungie-net.github.io/multi/ 。按名字找玩家用 POST /Destiny2/SearchDestinyPlayerByBungieName/-1/，body 是 {displayName, displayNameCode}。物品和活动的定义在 GET /Destiny2/Manifest/ 给的文件里，那些文件直接从 https://www.bungie.net 下载、不经这里，存进 /work 反复用。玩家没公开的（背包、仓库）看不到，也不能替人移动、装备物品。";
        };
      };
    };
  };

  # A switch of tank is judged by Max: its unit up as one process that says
  # it serves. Its migrations are what the max before can't run on: sqlx
  # refuses a database with a migration the binary doesn't know.
  my.systemDeploy.checks.maxx = {
    unit = "maxx.service";
    ready = "max: serving";
    before = deployBefore;
    after = deployAfter;
    irreversible = deployHook "migration" migration;
  };
}
