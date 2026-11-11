# The Rust rewrite of Max, as its own stack: its own user, database,
# directories and units, all named maxx. The Haskell max is gone from tank;
# its database and /var/lib/max stay for maxx's import.
# Design: docs/rust-rewrite.md on the max repo's maxx branch. It reaches QQ
# through Tencent's official bot API, as the bot maxx.
{
  config,
  lib,
  ...
}: let
  cliproxy = import ../../lib/cliproxy-models.nix {placement = config.my.fleet.placements.cliproxy;};
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
    # Vertex's global endpoint; promotional until 2026-11-30, then twice.
    gemini-4 = price 2 0.1 10;
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
in {
  sops.secrets =
    lib.genAttrs (map (name: "maxx/${name}") secretNames) (_: {
      sopsFile = ../../secrets/hosts/tank-max.yaml;
      owner = "maxx";
      restartUnits = ["maxx.service"];
    })
    // {
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

  # The rule that sends the operations network's VMs into its namespace
  # (maxx's module adds it too). networkd removes the ip rules its .network
  # files don't name whenever it configures a link: on 2026-11-06 it took
  # this one five seconds after boot, and those VMs were cut off until
  # 11-07. br-lan's file names it, br-lan being always configured.
  systemd.network.networks."30-br-lan".routingPolicyRules = [
    {
      From = "${config.services.maxx.vm.operations.subnet}.0/24";
      Table = 236;
      Priority = 236;
    }
  ];

  services.maxx = {
    enable = true;
    # The groups' VMs, where the tools run: 32 at a time, on taps from
    # 10.235.0.0/24.
    vm.enable = true;
    # SSH fleet operations (2026-11-05): these groups' VMs reach the fleet
    # with `ssh <host>` as max, through the maxops node of the Haskell max,
    # whose state was copied to /var/lib/maxx-ops-tailscale. Conversations
    # by maxx's ids, the groups' numbers being in its database only.
    vm.operations = {
      enable = true;
      conversations = [8 13];
      loginServer = "https://tailscale.imdomestic.com:8443";
      domain = "inner.imdomestic.com";
    };
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
        # Tidies each memory file Max wrote in the day, at 05:00.
        dreamer = {
          model = "cliproxy/gemini-3.8-flash-high";
          effort = "high";
        };
        # Says what each new picture and sticker shows; the Haskell max's
        # captioner too.
        caption = {
          model = "cliproxy-responses/gpt-5.6-luna";
          effort = "high";
        };
        # Background agents: pi in the groups' VMs, its model calls
        # forwarded by maxx with this provider's key. Rewind's model is
        # free, so they try it.
        job = {
          model = "cliproxy-responses/rewind/gpt-6-astra";
          effort = "xhigh";
        };
        # The Haskell max's models that see pictures, for /model; maxx
        # takes every model to see them. A window nobody wrote down is the
        # Haskell max's default, 131072.
        providers = {
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
                # Vertex AI; cap Max's budget at 256k for a 32k/16k chat tail.
                "vertex/gemini-4-argon" = {
                  context_window = 262144;
                  video = true;
                  price = prices.gemini-4;
                };
                "vertex-c820/gemini-4-argon" = {
                  context_window = 262144;
                  video = true;
                  price = prices.gemini-4;
                };
                "vertex-c820/gemini-4-carbon" = {
                  context_window = 262144;
                  video = true;
                  price = prices.gemini-4;
                };
              }
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
      # The sticker library's vectors: bge-m3 on h610's Ollama, the model
      # the Haskell max's vectors were made with.
      embedding = {
        base_url = "http://h610.inner.imdomestic.com:11434/v1";
        model = "bge-m3";
      };
    };
  };
}
