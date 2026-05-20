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

        /// <summary>CORS origins allowed to call this service. "*" allows all.</summary>
        public string[] AllowedOrigins { get; set; } = new[] { "*" };

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
