using System;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace VtechMFA
{
    internal static class CertManager
    {
        // Friendly name lets us locate the cert across restarts so we don't keep regenerating it.
        public const string CertFriendlyName = "VtechMFA-Localhost-HTTPS";
        public const string CertSubject = "CN=VtechMFA Localhost";
        // Stable AppID for netsh sslcert binding (any GUID is fine, but it must stay constant).
        public const string AppId = "{C351094F-D394-478E-86C3-C6928D616293}";

        public static X509Certificate2 EnsureCertificate(Action<string> log)
        {
            X509Certificate2 cert = FindExistingCert();
            if (cert != null && cert.NotAfter > DateTime.Now.AddDays(30))
            {
                log("Reusing existing certificate, thumbprint=" + cert.Thumbprint + ", expires=" + cert.NotAfter);
                return cert;
            }

            if (cert != null)
                log("Existing certificate near expiry. Regenerating.");

            cert = CreateSelfSignedCert();
            InstallCert(cert, StoreName.My, log);
            InstallCert(cert, StoreName.Root, log);
            log("Generated new certificate, thumbprint=" + cert.Thumbprint + ", expires=" + cert.NotAfter);
            return cert;
        }

        public static bool BindCertToPort(string ipPort, string thumbprint, Action<string> log)
        {
            // Delete any existing binding (ignore errors)
            RunNetsh("http delete sslcert ipport=" + ipPort, log, ignoreErrors: true);

            string args = string.Format(
                "http add sslcert ipport={0} certhash={1} appid={2} certstorename=MY",
                ipPort, thumbprint, AppId);

            return RunNetsh(args, log, ignoreErrors: false);
        }

        public static void EnsureUrlAcl(string url, Action<string> log)
        {
            // SYSTEM account gets the ACL since service runs as LocalSystem by default.
            // Use SID instead of localized name so this works on non-English Windows.
            const string systemSid = "S-1-5-18";
            RunNetsh("http delete urlacl url=" + url, log, ignoreErrors: true);
            RunNetsh("http add urlacl url=" + url + " sddl=D:(A;;GX;;;" + systemSid + ")", log, ignoreErrors: true);
        }

        private static X509Certificate2 FindExistingCert()
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                foreach (var c in store.Certificates)
                {
                    if (string.Equals(c.FriendlyName, CertFriendlyName, StringComparison.OrdinalIgnoreCase)
                        && c.HasPrivateKey)
                        return c;
                }
            }
            return null;
        }

        private static X509Certificate2 CreateSelfSignedCert()
        {
            using (RSA rsa = RSA.Create(2048))
            {
                var req = new CertificateRequest(
                    CertSubject, rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                var san = new SubjectAlternativeNameBuilder();
                san.AddDnsName("localhost");
                san.AddIpAddress(IPAddress.Loopback);
                san.AddIpAddress(IPAddress.IPv6Loopback);
                req.CertificateExtensions.Add(san.Build());

                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                req.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    critical: true));
                req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // Server Authentication
                    critical: false));

                using (X509Certificate2 ephemeral = req.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddDays(-1),
                    DateTimeOffset.UtcNow.AddYears(5)))
                {
                    ephemeral.FriendlyName = CertFriendlyName;

                    // Re-import via PFX so the private key is persisted to the machine key store.
                    string pwd = Guid.NewGuid().ToString("N");
                    byte[] pfx = ephemeral.Export(X509ContentType.Pfx, pwd);
                    var persisted = new X509Certificate2(
                        pfx, pwd,
                        X509KeyStorageFlags.MachineKeySet
                        | X509KeyStorageFlags.PersistKeySet
                        | X509KeyStorageFlags.Exportable);
                    persisted.FriendlyName = CertFriendlyName;
                    return persisted;
                }
            }
        }

        private static void InstallCert(X509Certificate2 cert, StoreName storeName, Action<string> log)
        {
            using (var store = new X509Store(storeName, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadWrite);
                // Remove any prior cert with the same friendly name to avoid pile-up on regeneration.
                foreach (var existing in store.Certificates)
                {
                    if (string.Equals(existing.FriendlyName, CertFriendlyName, StringComparison.OrdinalIgnoreCase))
                    {
                        try { store.Remove(existing); } catch { }
                    }
                }
                store.Add(cert);
                log("Installed cert into LocalMachine\\" + storeName);
            }
        }

        private static bool RunNetsh(string arguments, Action<string> log, bool ignoreErrors)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh", arguments)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                };
                using (var proc = Process.Start(psi))
                {
                    string outp = proc.StandardOutput.ReadToEnd();
                    string err = proc.StandardError.ReadToEnd();
                    proc.WaitForExit(10000);

                    if (!string.IsNullOrWhiteSpace(outp)) log("netsh: " + outp.Trim());
                    if (!string.IsNullOrWhiteSpace(err)) log("netsh err: " + err.Trim());

                    if (proc.ExitCode != 0 && !ignoreErrors)
                    {
                        log("netsh exited with code " + proc.ExitCode + " for: " + arguments);
                        return false;
                    }
                    return true;
                }
            }
            catch (Exception ex)
            {
                log("netsh execution failed: " + ex.Message);
                return ignoreErrors;
            }
        }
    }
}
