using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace VtechMFA
{
    /// <summary>
    /// Host-mediated ("data-mule") sync for the weight-scale device.
    ///
    /// The scale has no internet of its own. When it's plugged into this laptop
    /// over USB, it exposes a tiny plain-HTTP server on the USB-NCM link
    /// (default 192.168.137.x:8080) with:
    ///   GET  /info        -> { deviceId, deviceName, env, pending, fw }
    ///   GET  /sync/next   -> next pending invoice as cloud-ready JSON (X-Invoice-Id header), or 204
    ///   POST /sync/ack?invoice=ID -> mark that invoice synced
    ///
    /// This worker discovers the device (its fixed gadget MAC in the ARP table),
    /// pulls each pending invoice, uploads it to the cloud bulk API over HTTPS
    /// (which the laptop can do reliably), then acks the device.
    /// </summary>
    internal sealed class WeightScaleSync
    {
        // Fixed locally-administered MAC the device's USB gadget uses (see firmware
        // USB_NET_MAC_* in app_config.h). ARP shows it as the device's link address.
        private const string GadgetMac = "02-00-00-12-34-56";

        private readonly Config _cfg;
        private readonly Action<string> _log;
        private readonly HttpClient _device;   // plain HTTP to the scale (short timeout)
        private readonly HttpClient _cloud;    // HTTPS to the server

        public WeightScaleSync(Config cfg, Action<string> log)
        {
            _cfg = cfg;
            _log = log;

            try { ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12; } catch { }

            _device = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            _cloud = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        }

        public async Task RunLoopAsync(CancellationToken token)
        {
            _log("[WS] Weight-scale sync worker started (poll " + _cfg.WeightScalePollSeconds + "s).");
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await SyncOnceAsync(token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _log("[WS] cycle error: " + ex.Message);
                }

                try { await Task.Delay(TimeSpan.FromSeconds(Math.Max(5, _cfg.WeightScalePollSeconds)), token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
            _log("[WS] Weight-scale sync worker stopped.");
        }

        private async Task SyncOnceAsync(CancellationToken token)
        {
            string ip = await FindDeviceIpAsync(token).ConfigureAwait(false);
            if (ip == null) return;   // no scale connected right now

            string baseUrl = "http://" + ip + ":" + _cfg.WeightScaleDevicePort;

            // ---- /info ----
            JsonElement info;
            try
            {
                string infoJson = await _device.GetStringAsync(baseUrl + "/info").ConfigureAwait(false);
                using (var doc = JsonDocument.Parse(infoJson)) info = doc.RootElement.Clone();
            }
            catch (Exception ex)
            {
                _log("[WS] /info failed at " + ip + ": " + ex.Message);
                return;
            }

            int pending = info.TryGetProperty("pending", out var p) ? p.GetInt32() : 0;
            string env = info.TryGetProperty("env", out var e) ? (e.GetString() ?? "dev") : "dev";
            string devName = info.TryGetProperty("deviceName", out var dn) ? dn.GetString() : "";
            if (pending <= 0) return;

            _log("[WS] device '" + devName + "' @ " + ip + " has " + pending + " pending (" + env + ")");

            string bulkUrl = env.Equals("prod", StringComparison.OrdinalIgnoreCase)
                ? _cfg.WeightScaleProdBulkUrl : _cfg.WeightScaleDevBulkUrl;
            string healthUrl = env.Equals("prod", StringComparison.OrdinalIgnoreCase)
                ? _cfg.WeightScaleProdHealthUrl : _cfg.WeightScaleDevHealthUrl;

            // ---- cloud reachable? (parity with the device's own flow) ----
            if (!await CloudHealthyAsync(healthUrl, token).ConfigureAwait(false))
            {
                _log("[WS] cloud not healthy (" + healthUrl + ") — will retry next cycle");
                return;
            }

            // ---- drain pending invoices: pull -> upload -> ack ----
            int uploaded = 0;
            for (int i = 0; i < 200 && !token.IsCancellationRequested; i++)
            {
                var next = await GetNextPayloadAsync(baseUrl + "/sync/next", token).ConfigureAwait(false);
                string payload = next.Item1;
                string invoiceId = next.Item2;
                if (payload == null) break;   // 204 -> nothing left

                bool ok = await PostCloudAsync(bulkUrl, payload, token).ConfigureAwait(false);
                if (!ok)
                {
                    _log("[WS] cloud upload failed for invoice " + invoiceId + " — stopping, will retry");
                    break;
                }

                await AckAsync(baseUrl + "/sync/ack?invoice=" + invoiceId, token).ConfigureAwait(false);
                uploaded++;
                _log("[WS] uploaded + acked invoice " + invoiceId);
            }

            if (uploaded > 0) _log("[WS] cycle done: " + uploaded + " invoice(s) synced from " + ip);
        }

        // Returns (payload, invoiceId). payload is null on 204/empty (nothing left).
        // GetStringAsync doesn't give headers/status, so do a manual request to read
        // 204 (done) and the X-Invoice-Id header.
        private async Task<Tuple<string, string>> GetNextPayloadAsync(string url, CancellationToken token)
        {
            string invoiceId = null;
            using (var resp = await _device.GetAsync(url, token).ConfigureAwait(false))
            {
                if (resp.StatusCode == HttpStatusCode.NoContent) return Tuple.Create<string, string>(null, null);
                if (!resp.IsSuccessStatusCode) return Tuple.Create<string, string>(null, null);

                if (resp.Headers.TryGetValues("X-Invoice-Id", out var vals))
                    foreach (var v in vals) { invoiceId = v; break; }

                string body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(body)) return Tuple.Create<string, string>(null, null);

                // Fall back to parsing invoiceId from the body if the header was absent.
                if (invoiceId == null)
                {
                    try { using (var d = JsonDocument.Parse(body))
                        if (d.RootElement.TryGetProperty("invoiceId", out var inv)) invoiceId = inv.ToString(); }
                    catch { }
                }
                return invoiceId == null ? Tuple.Create<string, string>(null, null) : Tuple.Create(body, invoiceId);
            }
        }

        private async Task<bool> CloudHealthyAsync(string healthUrl, CancellationToken token)
        {
            if (string.IsNullOrWhiteSpace(healthUrl)) return true;  // health check optional
            try
            {
                using (var resp = await _cloud.GetAsync(healthUrl, token).ConfigureAwait(false))
                {
                    if (!resp.IsSuccessStatusCode) return false;
                    string body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                    return body != null && body.IndexOf("Healthy", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            catch (Exception ex) { _log("[WS] health check failed: " + ex.Message); return false; }
        }

        private async Task<bool> PostCloudAsync(string url, string json, CancellationToken token)
        {
            try
            {
                using (var content = new StringContent(json, Encoding.UTF8, "application/json"))
                using (var resp = await _cloud.PostAsync(url, content, token).ConfigureAwait(false))
                {
                    if (resp.IsSuccessStatusCode) return true;
                    _log("[WS] cloud POST " + (int)resp.StatusCode + " " + url);
                    return false;
                }
            }
            catch (Exception ex) { _log("[WS] cloud POST error: " + ex.Message); return false; }
        }

        private async Task AckAsync(string url, CancellationToken token)
        {
            try
            {
                using (var resp = await _device.PostAsync(url, new StringContent(""), token).ConfigureAwait(false))
                {
                    if (!resp.IsSuccessStatusCode) _log("[WS] ack returned " + (int)resp.StatusCode);
                }
            }
            catch (Exception ex) { _log("[WS] ack error: " + ex.Message); }
        }

        // ---- device discovery ----------------------------------------------------

        /// <summary>
        /// Find the scale's IP. First the ARP table (the gadget MAC appears there once
        /// the device has done DHCP), then a quick parallel /info probe of the ICS /24
        /// as a fallback if the ARP entry has aged out.
        /// </summary>
        private async Task<string> FindDeviceIpAsync(CancellationToken token)
        {
            // 1) Fixed static IP (firmware self-assigns it) — instant, no DHCP/ARP.
            if (!string.IsNullOrWhiteSpace(_cfg.WeightScaleStaticIp)
                && await IsDeviceAtAsync(_cfg.WeightScaleStaticIp, token).ConfigureAwait(false))
                return _cfg.WeightScaleStaticIp;

            // 2) ARP table (works if the device used DHCP).
            string fromArp = FindIpInArpTable();
            if (fromArp != null) return fromArp;

            // 3) Last resort: probe the ICS subnet.
            return await ProbeIcsSubnetAsync(token).ConfigureAwait(false);
        }

        private async Task<bool> IsDeviceAtAsync(string ip, CancellationToken token)
        {
            try
            {
                using (var probe = new HttpClient { Timeout = TimeSpan.FromMilliseconds(1500) })
                {
                    string body = await probe.GetStringAsync("http://" + ip + ":" + _cfg.WeightScaleDevicePort + "/info").ConfigureAwait(false);
                    return body != null && body.IndexOf("deviceId", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            catch { return false; }
        }

        private string FindIpInArpTable()
        {
            try
            {
                var psi = new ProcessStartInfo("arp", "-a")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                using (var proc = Process.Start(psi))
                {
                    string outp = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(5000);

                    foreach (var raw in outp.Split('\n'))
                    {
                        string line = raw.Trim();
                        if (line.IndexOf(GadgetMac, StringComparison.OrdinalIgnoreCase) < 0) continue;
                        var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 1 && IPAddress.TryParse(parts[0], out _)) return parts[0];
                    }
                }
            }
            catch (Exception ex) { _log("[WS] arp parse failed: " + ex.Message); }
            return null;
        }

        // Find the local interface on the ICS subnet (192.168.137.0/24 by default) and
        // probe every host for a weight-scale /info. Returns the first match.
        private async Task<string> ProbeIcsSubnetAsync(CancellationToken token)
        {
            string prefix = _cfg.WeightScaleSubnetPrefix;   // e.g. "192.168.137."
            if (string.IsNullOrWhiteSpace(prefix)) return null;

            // Only probe if this machine actually has an interface on that subnet (ICS host).
            bool onSubnet = false;
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                        && ua.Address.ToString().StartsWith(prefix, StringComparison.Ordinal))
                    { onSubnet = true; break; }
                if (onSubnet) break;
            }
            if (!onSubnet) return null;

            var probe = new HttpClient { Timeout = TimeSpan.FromMilliseconds(400) };
            try
            {
                var tasks = new System.Collections.Generic.List<Task<string>>();
                for (int host = 2; host <= 254; host++)
                {
                    string ip = prefix + host;
                    tasks.Add(ProbeOneAsync(probe, ip, token));
                }
                foreach (var t in tasks)
                {
                    string hit = await t.ConfigureAwait(false);
                    if (hit != null) return hit;
                }
            }
            finally { probe.Dispose(); }
            return null;
        }

        private async Task<string> ProbeOneAsync(HttpClient probe, string ip, CancellationToken token)
        {
            try
            {
                string url = "http://" + ip + ":" + _cfg.WeightScaleDevicePort + "/info";
                string body = await probe.GetStringAsync(url).ConfigureAwait(false);
                if (body != null && body.IndexOf("deviceId", StringComparison.OrdinalIgnoreCase) >= 0
                    && body.IndexOf("pending", StringComparison.OrdinalIgnoreCase) >= 0)
                    return ip;
            }
            catch { }
            return null;
        }
    }
}
