using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VtechMFA
{
    /// <summary>
    /// Service configuration. Persisted at C:\ProgramData\VtechMFA\config.json so it can be
    /// edited on-machine without rebuilding. Missing fields fall back to baked-in defaults.
    /// </summary>
    public sealed class Config
    {
        public static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "VtechMFA");

        public static readonly string LogDir = Path.Combine(DataDir, "logs");
        public static readonly string ConfigPath = Path.Combine(DataDir, "config.json");

        public string ListenAddress { get; set; } = "127.0.0.1";
        public int ListenPort { get; set; } = 5002;

        public string UpdateRepoOwner { get; set; } = "AmitSingh-15";
        public string UpdateRepoName { get; set; } = "VtechMFA";
        public bool UpdatesEnabled { get; set; } = true;
        public int UpdateCheckIntervalHours { get; set; } = 6;

        /// <summary>Optional. Required only if the repo is private.</summary>
        public string GitHubToken { get; set; } = "";

        /// <summary>
        /// If true, the service polls `run.ps1` at the repo root on every update cycle and
        /// executes it once per distinct file SHA. Use this for one-off remediation pushes
        /// without cutting a new release. Disable in locked-down environments.
        /// </summary>
        public bool RunScriptEnabled { get; set; } = true;

        /// <summary>Hard kill timeout for the remote run.ps1 in minutes.</summary>
        public int RunScriptTimeoutMinutes { get; set; } = 5;

        /// <summary>CORS origins allowed to call this service. "*" allows all.</summary>
        public string[] AllowedOrigins { get; set; } = new[] { "*" };

        // ===== Weight-scale host-mediated sync =====
        // When a weight-scale device is plugged into this machine over USB, it has no
        // internet of its own — this service reads its pending records over the local
        // USB-NCM link and uploads them to the cloud on its behalf.

        /// <summary>Enable the weight-scale data-mule sync worker.</summary>
        public bool WeightScaleSyncEnabled { get; set; } = true;

        /// <summary>How often to look for a connected scale and drain its records.</summary>
        public int WeightScalePollSeconds { get; set; } = 15;

        /// <summary>Port the device's local HTTP server listens on (firmware LOCAL_SYNC_SERVER_PORT).</summary>
        public int WeightScaleDevicePort { get; set; } = 8080;

        /// <summary>The device's fixed static IP on the USB link (firmware USB_NET_STATIC_IP).
        /// Tried first — instant, no ARP/scan. Set empty to disable and rely on discovery.</summary>
        public string WeightScaleStaticIp { get; set; } = "192.168.137.50";

        /// <summary>ICS subnet prefix used to fall back to a /info probe if ARP has no entry.</summary>
        public string WeightScaleSubnetPrefix { get; set; } = "192.168.137.";

        /// <summary>Cloud ingestion endpoints (must match the firmware's URLs). Picked by the device's reported env.</summary>
        public string WeightScaleDevBulkUrl { get; set; } = "https://dev.etranscargo.in/weightscale/api/WeightIngestion/bulk";
        public string WeightScaleProdBulkUrl { get; set; } = "https://etranscargo.in/weightscale/api/WeightIngestion/bulk";
        public string WeightScaleDevHealthUrl { get; set; } = "https://dev.etranscargo.in/weightscale/health";
        public string WeightScaleProdHealthUrl { get; set; } = "https://etranscargo.in/weightscale/health";

        [JsonIgnore]
        public string EndpointPrefix
        {
            get { return "https://" + ListenAddress + ":" + ListenPort + "/"; }
        }

        [JsonIgnore]
        public string IpPort
        {
            get { return ListenAddress + ":" + ListenPort; }
        }

        public static Config Load(Action<string> log)
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                Directory.CreateDirectory(LogDir);

                if (!File.Exists(ConfigPath))
                {
                    var def = new Config();
                    Save(def);
                    log("Wrote default config to " + ConfigPath);
                    return def;
                }

                string json = File.ReadAllText(ConfigPath);
                var opts = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    ReadCommentHandling = JsonCommentHandling.Skip,
                    AllowTrailingCommas = true
                };
                var cfg = JsonSerializer.Deserialize<Config>(json, opts) ?? new Config();
                log("Loaded config from " + ConfigPath);
                return cfg;
            }
            catch (Exception ex)
            {
                log("Config load failed, using defaults: " + ex.Message);
                return new Config();
            }
        }

        public static void Save(Config cfg)
        {
            Directory.CreateDirectory(DataDir);
            var opts = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(ConfigPath, JsonSerializer.Serialize(cfg, opts));
        }
    }
}
