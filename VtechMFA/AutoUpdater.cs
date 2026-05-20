using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace VtechMFA
{
    /// <summary>
    /// Periodically polls a GitHub Releases feed and self-replaces the service when a newer
    /// release is available. The replace step shells out to an updater script that waits for
    /// this process to exit, copies the staged files in, and restarts the service.
    /// </summary>
    internal sealed class AutoUpdater
    {
        private readonly Config _config;
        private readonly Action<string> _log;
        private readonly HttpClient _http;

        public AutoUpdater(Config config, Action<string> log)
        {
            _config = config;
            _log = log;

            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            _http = new HttpClient();
            _http.Timeout = TimeSpan.FromMinutes(5);
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("VtechMFA-Updater/1.0");
            _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            if (!string.IsNullOrWhiteSpace(_config.GitHubToken))
                _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _config.GitHubToken);
        }

        public async Task RunLoopAsync(CancellationToken token)
        {
            // Short delay on boot so the service is fully up before we check.
            try { await Task.Delay(TimeSpan.FromMinutes(2), token); }
            catch (OperationCanceledException) { return; }

            while (!token.IsCancellationRequested)
            {
                try
                {
                    if (_config.UpdatesEnabled)
                        await CheckOnceAsync(token);
                }
                catch (Exception ex)
                {
                    _log("Update check failed: " + ex.Message);
                }

                try
                {
                    var interval = TimeSpan.FromHours(Math.Max(1, _config.UpdateCheckIntervalHours));
                    await Task.Delay(interval, token);
                }
                catch (OperationCanceledException) { return; }
            }
        }

        public async Task<bool> CheckOnceAsync(CancellationToken token)
        {
            _log("Checking for updates from github.com/" + _config.UpdateRepoOwner + "/" + _config.UpdateRepoName);

            string url = "https://api.github.com/repos/" + _config.UpdateRepoOwner + "/" + _config.UpdateRepoName + "/releases/latest";

            string body;
            using (var resp = await _http.GetAsync(url, token))
            {
                if (resp.StatusCode == HttpStatusCode.NotFound)
                {
                    _log("No releases published yet — skipping.");
                    return false;
                }
                resp.EnsureSuccessStatusCode();
                body = await resp.Content.ReadAsStringAsync();
            }

            using (JsonDocument doc = JsonDocument.Parse(body))
            {
                JsonElement root = doc.RootElement;
                if (!root.TryGetProperty("tag_name", out JsonElement tagEl))
                {
                    _log("Release payload missing tag_name.");
                    return false;
                }
                string tag = tagEl.GetString() ?? "";
                Version remoteVersion = ParseVersion(tag);
                Version localVersion = Assembly.GetExecutingAssembly().GetName().Version;

                if (remoteVersion == null)
                {
                    _log("Could not parse remote version from tag '" + tag + "'. Skipping.");
                    return false;
                }

                _log("Local version: " + localVersion + ", remote: " + remoteVersion + " (tag " + tag + ")");

                if (remoteVersion <= localVersion)
                {
                    _log("Already up to date.");
                    return false;
                }

                JsonElement assets;
                if (!root.TryGetProperty("assets", out assets) || assets.GetArrayLength() == 0)
                {
                    _log("Newer release has no assets to download.");
                    return false;
                }

                string zipUrl = null;
                string zipName = null;
                string sha256Url = null;
                foreach (var a in assets.EnumerateArray())
                {
                    string name = a.GetProperty("name").GetString() ?? "";
                    string dlUrl = a.GetProperty("browser_download_url").GetString() ?? "";
                    if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && zipUrl == null)
                    {
                        zipUrl = dlUrl; zipName = name;
                    }
                    else if (name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase) && sha256Url == null)
                    {
                        sha256Url = dlUrl;
                    }
                }

                if (zipUrl == null)
                {
                    _log("No .zip asset found on release " + tag + ".");
                    return false;
                }

                _log("Downloading update asset: " + zipName);
                string stagingRoot = Path.Combine(Config.DataDir, "update");
                if (Directory.Exists(stagingRoot)) TryDeleteDir(stagingRoot);
                Directory.CreateDirectory(stagingRoot);

                string zipPath = Path.Combine(stagingRoot, zipName);
                await DownloadAsync(zipUrl, zipPath, token);

                if (sha256Url != null)
                {
                    string expectedHash = (await _http.GetStringAsync(sha256Url)).Trim().Split(' ')[0];
                    string actualHash = ComputeSha256(zipPath);
                    if (!string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase))
                    {
                        _log("SHA256 mismatch. Expected " + expectedHash + ", got " + actualHash + ". Aborting update.");
                        return false;
                    }
                    _log("SHA256 verified.");
                }

                string extractDir = Path.Combine(stagingRoot, "staging");
                Directory.CreateDirectory(extractDir);
                ZipFile.ExtractToDirectory(zipPath, extractDir);

                // If the zip nested everything in one root folder, flatten it.
                var entries = Directory.GetFileSystemEntries(extractDir);
                if (entries.Length == 1 && Directory.Exists(entries[0]))
                {
                    extractDir = entries[0];
                }

                ApplyUpdate(extractDir, remoteVersion);
                return true;
            }
        }

        private void ApplyUpdate(string stagingDir, Version newVersion)
        {
            string installDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string scriptDir = Path.Combine(Config.DataDir, "update");
            string scriptPath = Path.Combine(scriptDir, "apply_update.cmd");
            string logPath = Path.Combine(Config.LogDir, "updater.log");
            string serviceName = VtechMFAService.ServiceNameConst;

            // Updater script. Retries the file copy because Windows may still hold file handles
            // for a few hundred ms after `net stop` returns.
            string script =
@"@echo off
setlocal EnableDelayedExpansion
set LOG=""" + logPath + @"""
echo [%date% %time%] Updater starting for v" + newVersion + @" >> %LOG%

net stop """ + serviceName + @""" >> %LOG% 2>&1
timeout /t 5 /nobreak > nul

set /a tries=0
:copy_loop
xcopy /Y /E /I /Q """ + stagingDir + @"\*"" """ + installDir + @"\"" >> %LOG% 2>&1
if not errorlevel 1 goto copy_ok
set /a tries+=1
if !tries! lss 6 (
  echo [%date% %time%] xcopy retry !tries! >> %LOG%
  timeout /t 3 /nobreak > nul
  goto copy_loop
)
echo [%date% %time%] xcopy failed after retries >> %LOG%
goto cleanup

:copy_ok
echo [%date% %time%] Copy ok, starting service... >> %LOG%
net start """ + serviceName + @""" >> %LOG% 2>&1

:cleanup
echo [%date% %time%] Updater finished >> %LOG%
(goto) 2>nul & del ""%~f0""
";

            File.WriteAllText(scriptPath, script);
            _log("Launching updater script: " + scriptPath);

            // Use `start` to detach the script from this process's job, so it survives our exit.
            var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe",
                "/c start \"\" /b cmd.exe /c \"" + scriptPath + "\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
            };
            System.Diagnostics.Process.Start(psi);

            // The script will call `net stop` which signals OnStop on the service.
            // We don't kill the process here — Windows SCM will drive the shutdown.
        }

        private async Task DownloadAsync(string url, string dest, CancellationToken token)
        {
            using (var resp = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token))
            {
                resp.EnsureSuccessStatusCode();
                using (var s = await resp.Content.ReadAsStreamAsync())
                using (var f = File.Create(dest))
                {
                    await s.CopyToAsync(f, 81920, token);
                }
            }
        }

        private static string ComputeSha256(string path)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            using (var s = File.OpenRead(path))
            {
                byte[] hash = sha.ComputeHash(s);
                var sb = new System.Text.StringBuilder(hash.Length * 2);
                foreach (byte b in hash) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        private static Version ParseVersion(string tag)
        {
            if (string.IsNullOrWhiteSpace(tag)) return null;
            string clean = tag.TrimStart('v', 'V').Trim();
            // Strip any pre-release / build suffix (e.g. 1.2.3-rc1 -> 1.2.3)
            int dash = clean.IndexOfAny(new[] { '-', '+' });
            if (dash > 0) clean = clean.Substring(0, dash);

            // Normalize partial versions like "1.2" -> "1.2.0.0"
            int dots = clean.Count(c => c == '.');
            while (dots < 3) { clean += ".0"; dots++; }

            Version v;
            return Version.TryParse(clean, out v) ? v : null;
        }

        private static void TryDeleteDir(string path)
        {
            try { Directory.Delete(path, recursive: true); }
            catch { }
        }
    }
}
