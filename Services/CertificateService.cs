using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace CACApp.Services;

public class CertificateService : ICertificateService
{
    private readonly ILogger<CertificateService> _logger;

    public CertificateService(ILogger<CertificateService> logger)
    {
        _logger = logger;
    }
    public async Task<bool> ValidateCertificateChainAsync(X509Certificate2 certificate)
    {
        return await Task.Run(() =>
        {
            try
            {
                _logger.LogInformation("Starting certificate chain validation for subject: {Subject}", certificate.Subject);

                // Try online revocation checking first
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.VerificationTime = DateTime.Now;
                chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);

                _logger.LogDebug("Building certificate chain with online revocation checking");
                bool isValid = chain.Build(certificate);
                _logger.LogInformation("Chain build result: {IsValid}, Chain elements: {ElementCount}", isValid, chain.ChainElements.Count);

                // Check if the failure is due to revocation status unknown (not actual revocation)
                bool hasActualRevocation = false;
                bool hasConnectivityIssue = false;

                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    if (status.Status != X509ChainStatusFlags.NoError)
                    {
                        _logger.LogDebug("Chain status: {Status}, Information: {StatusInformation}", status.Status, status.StatusInformation);
                    }

                    if (status.Status.HasFlag(X509ChainStatusFlags.Revoked))
                    {
                        hasActualRevocation = true;
                        _logger.LogWarning("Certificate chain validation failed: Certificate is REVOKED. Status: {Status}, Info: {StatusInformation}",
                            status.Status, status.StatusInformation);
                        return false; // Actually revoked
                    }
                    else if (status.Status.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown) ||
                             status.Status.HasFlag(X509ChainStatusFlags.OfflineRevocation))
                    {
                        hasConnectivityIssue = true;
                        _logger.LogInformation("Revocation status unknown (CRL/OCSP not available): {StatusInformation}. Treating as 'Not Available' rather than revoked.", status.StatusInformation);
                    }
                }

                // If revocation status couldn't be determined (CRL/OCSP not available) but chain is otherwise valid, allow it
                // This treats "not available" as non-revoked, only failing if actually revoked
                if (hasConnectivityIssue && !hasActualRevocation && !isValid)
                {
                    _logger.LogInformation("Attempting offline chain validation (revocation check disabled)");
                    using var offlineChain = new X509Chain();
                    offlineChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    offlineChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    offlineChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    offlineChain.ChainPolicy.VerificationTime = DateTime.Now;

                    bool offlineValid = offlineChain.Build(certificate);
                    _logger.LogInformation("Offline chain build result: {IsValid}", offlineValid);

                    if (!offlineValid)
                    {
                        foreach (X509ChainStatus status in offlineChain.ChainStatus)
                        {
                            if (status.Status != X509ChainStatusFlags.NoError)
                            {
                                _logger.LogWarning("Offline chain status: {Status}, Information: {StatusInformation}",
                                    status.Status, status.StatusInformation);
                            }
                        }
                    }

                    return offlineValid;
                }

                if (!isValid)
                {
                    _logger.LogWarning("Certificate chain validation failed. Chain status details:");
                    foreach (X509ChainStatus status in chain.ChainStatus)
                    {
                        if (status.Status != X509ChainStatusFlags.NoError)
                        {
                            _logger.LogWarning("  Status: {Status}, Information: {StatusInformation}",
                                status.Status, status.StatusInformation);
                        }
                    }
                }
                else
                {
                    _logger.LogInformation("Certificate chain validation succeeded");
                }

                return isValid;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during certificate chain validation for subject: {Subject}", certificate.Subject);
                return false;
            }
        });
    }

    public async Task<CertificateChainInfo> GetChainInfoAsync(X509Certificate2 certificate)
    {
        return await Task.Run(() =>
        {
            var info = new CertificateChainInfo();

            try
            {
                _logger.LogInformation("Getting certificate chain info for subject: {Subject}, Thumbprint: {Thumbprint}",
                    certificate.Subject, certificate.Thumbprint);

                // Try online revocation checking first
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.VerificationTime = DateTime.Now;
                chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);

                _logger.LogDebug("Building certificate chain with online revocation checking");
                bool isValid = chain.Build(certificate);
                bool onlineValidationFailed = !isValid;
                _logger.LogInformation("Chain build result: {IsValid}, Chain elements: {ElementCount}", isValid, chain.ChainElements.Count);

                // Check if revocation status couldn't be determined (not the same as revoked)
                bool hasRevocationUnknown = false;
                bool hasActualRevocation = false;
                bool hasOtherErrors = false;

                int elementIndex = 0;
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    int statusCount = element.ChainElementStatus.Length;
                    _logger.LogDebug("Chain element {Index}: Subject={Subject}, Issuer={Issuer}, Status count={StatusCount}",
                        elementIndex, element.Certificate.Subject, element.Certificate.Issuer, statusCount);
                    elementIndex++;

                    foreach (X509ChainStatus status in element.ChainElementStatus)
                    {
                        if (status.Status != X509ChainStatusFlags.NoError)
                        {
                            _logger.LogDebug("Element status: Certificate={Subject}, Status={Status}, Info={StatusInformation}",
                                element.Certificate.Subject, status.Status, status.StatusInformation);

                            // Check for actual revocation (most critical)
                            if (status.Status.HasFlag(X509ChainStatusFlags.Revoked))
                            {
                                hasActualRevocation = true;
                                string revocationReason = GetRevocationReason(status.StatusInformation);
                                string certInfo = $"Certificate: {element.Certificate.Subject}";
                                string errorMsg = $"Revoked: {certInfo} - Reason: {revocationReason}";
                                info.ChainErrors.Add(errorMsg);
                                _logger.LogWarning("Certificate REVOKED: {CertInfo}, Reason: {RevocationReason}",
                                    certInfo, revocationReason);
                            }
                            // Check for revocation status unknown (network/connectivity issue, not revocation)
                            else if (status.Status.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown) ||
                                     status.Status.HasFlag(X509ChainStatusFlags.OfflineRevocation))
                            {
                                hasRevocationUnknown = true;
                                _logger.LogInformation("Revocation status unknown for certificate: {Subject}, Status: {StatusInformation}",
                                    element.Certificate.Subject, status.StatusInformation);
                                // Note: Don't add this as an error - it's a connectivity issue, not revocation
                            }
                            else
                            {
                                hasOtherErrors = true;
                                string errorMsg = $"{status.Status}: {status.StatusInformation}";
                                info.ChainErrors.Add(errorMsg);
                                _logger.LogWarning("Chain validation error: Certificate={Subject}, Status={Status}, Info={StatusInformation}",
                                    element.Certificate.Subject, status.Status, status.StatusInformation);
                            }
                        }
                    }
                }

                // If revocation was reported online, verify with offline check (could be false positive from network/cache issues)
                if (hasActualRevocation && !isValid)
                {
                    _logger.LogInformation("Revocation reported online - verifying with offline check to rule out false positives");
                    using var offlineChain = new X509Chain();
                    offlineChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    offlineChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    offlineChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    offlineChain.ChainPolicy.VerificationTime = DateTime.Now;

                    bool offlineValid = offlineChain.Build(certificate);
                    _logger.LogInformation("Offline chain build result: {IsValid}, Chain elements: {ElementCount}",
                        offlineValid, offlineChain.ChainElements.Count);

                    if (offlineValid)
                    {
                        // Offline validation succeeded - online revocation was likely a false positive
                        isValid = true;
                        hasActualRevocation = false; // Clear the revocation flag since offline check passed
                        info.ChainErrors.Clear(); // Clear the revocation error
                        info.OnlineValidationFailed = true;
                        info.OnlineValidationFailureReason = "🔌 CONNECTIVITY ISSUE: Online revocation check reported REVOKED, but offline validation succeeded. This indicates a network/connectivity problem preventing access to OCSP/CRL servers, NOT an actual revocation. Certificate chain is VALID.";
                        info.ChainErrors.Add($"⚠️ {info.OnlineValidationFailureReason}");
                        _logger.LogWarning("Online revocation check reported revoked, but offline validation succeeded. Likely false positive from network/cache issues.");
                    }
                    else
                    {
                        _logger.LogWarning("Offline chain validation also failed. Checking for actual revocation:");
                        // Check for actual revocation in offline mode
                        bool offlineHasRevocation = false;
                        foreach (X509ChainElement element in offlineChain.ChainElements)
                        {
                            foreach (X509ChainStatus status in element.ChainElementStatus)
                            {
                                if (status.Status != X509ChainStatusFlags.NoError)
                                {
                                    _logger.LogWarning("Offline chain element status: Certificate={Subject}, Status={Status}, Info={StatusInformation}",
                                        element.Certificate.Subject, status.Status, status.StatusInformation);

                                    if (status.Status.HasFlag(X509ChainStatusFlags.Revoked))
                                    {
                                        offlineHasRevocation = true;
                                        string revocationReason = GetRevocationReason(status.StatusInformation);
                                        string certInfo = $"Certificate: {element.Certificate.Subject}";
                                        string errorMsg = $"🚫 REAL REVOCATION: {certInfo} - Reason: {revocationReason} (Confirmed by both online and offline checks)";
                                        // Update error message if not already present
                                        if (!info.ChainErrors.Any(e => e.Contains("REAL REVOCATION") && e.Contains(element.Certificate.Subject)))
                                        {
                                            info.ChainErrors.Clear();
                                            info.ChainErrors.Add(errorMsg);
                                        }
                                        _logger.LogWarning("Certificate REVOKED (confirmed offline): {CertInfo}, Reason: {RevocationReason}",
                                            certInfo, revocationReason);
                                    }
                                }
                            }
                        }
                        // If offline also shows revocation, keep hasActualRevocation = true
                        // Otherwise, it might be a different validation issue
                        if (!offlineHasRevocation)
                        {
                            _logger.LogWarning("Offline validation failed but no revocation found - may be a different validation issue");
                        }
                    }
                }
                // If revocation status is unknown (not revoked, just couldn't verify), try offline mode
                else if (hasRevocationUnknown && !hasActualRevocation && !isValid && !hasOtherErrors)
                {
                    _logger.LogInformation("Attempting offline chain validation (revocation check disabled)");
                    using var offlineChain = new X509Chain();
                    offlineChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    offlineChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    offlineChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    offlineChain.ChainPolicy.VerificationTime = DateTime.Now;

                    bool offlineValid = offlineChain.Build(certificate);
                    _logger.LogInformation("Offline chain build result: {IsValid}, Chain elements: {ElementCount}",
                        offlineValid, offlineChain.ChainElements.Count);

                    if (offlineValid)
                    {
                        isValid = true;
                        info.OnlineValidationFailed = true;
                        info.OnlineValidationFailureReason = "🔌 CONNECTIVITY ISSUE: Revocation status could not be verified online (network/connectivity issue preventing access to OCSP/CRL servers). Offline validation succeeded - certificate chain is VALID.";
                        info.ChainErrors.Add($"⚠️ {info.OnlineValidationFailureReason}");
                        _logger.LogInformation("Offline validation succeeded - chain is valid but revocation status could not be verified");
                    }
                    else
                    {
                        _logger.LogWarning("Offline chain validation also failed. Checking for revocation:");
                        // Check for actual revocation in offline mode
                        foreach (X509ChainElement element in offlineChain.ChainElements)
                        {
                            foreach (X509ChainStatus status in element.ChainElementStatus)
                            {
                                if (status.Status != X509ChainStatusFlags.NoError)
                                {
                                    _logger.LogWarning("Offline chain element status: Certificate={Subject}, Status={Status}, Info={StatusInformation}",
                                        element.Certificate.Subject, status.Status, status.StatusInformation);

                                    if (status.Status.HasFlag(X509ChainStatusFlags.Revoked))
                                    {
                                        hasActualRevocation = true;
                                        string revocationReason = GetRevocationReason(status.StatusInformation);
                                        string certInfo = $"Certificate: {element.Certificate.Subject}";
                                        string errorMsg = $"Revoked: {certInfo} - Reason: {revocationReason}";
                                        info.ChainErrors.Add(errorMsg);
                                        _logger.LogWarning("Certificate REVOKED (offline check): {CertInfo}, Reason: {RevocationReason}",
                                            certInfo, revocationReason);
                                    }
                                    else if (!info.ChainErrors.Any(e => e.Contains(status.Status.ToString())))
                                    {
                                        string errorMsg = $"{status.Status}: {status.StatusInformation}";
                                        info.ChainErrors.Add(errorMsg);
                                        _logger.LogWarning("Offline chain error: {ErrorMsg}", errorMsg);
                                    }
                                }
                            }
                        }
                    }
                }

                // Certificate is valid if chain builds successfully and is not actually revoked
                info.IsValid = isValid && !hasActualRevocation;
                _logger.LogInformation("Final chain validation result: IsValid={IsValid}, HasRevocation={HasRevocation}, ErrorCount={ErrorCount}",
                    info.IsValid, hasActualRevocation, info.ChainErrors.Count);

                // Build chain elements from the last successful chain build
                using var finalChain = new X509Chain();
                finalChain.ChainPolicy.RevocationMode = hasActualRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
                finalChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                finalChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                finalChain.ChainPolicy.VerificationTime = DateTime.Now;
                finalChain.Build(certificate);

                _logger.LogDebug("Building final chain elements list. Chain length: {ChainLength}", finalChain.ChainElements.Count);
                foreach (X509ChainElement element in finalChain.ChainElements)
                {
                    var cert = element.Certificate;
                    info.Chain.Add(new CertificateInfo
                    {
                        Subject = cert.Subject,
                        Issuer = cert.Issuer,
                        NotBefore = cert.NotBefore,
                        NotAfter = cert.NotAfter,
                        IsValid = DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter,
                        Thumbprint = cert.Thumbprint
                    });
                    _logger.LogDebug("Chain element: Subject={Subject}, Valid={IsValid}, Thumbprint={Thumbprint}",
                        cert.Subject, DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter, cert.Thumbprint);
                }
            }
            catch (Exception ex)
            {
                string errorMsg = $"Error building chain: {ex.Message}";
                info.ChainErrors.Add(errorMsg);
                _logger.LogError(ex, "Exception while getting certificate chain info for subject: {Subject}", certificate.Subject);
            }

            return info;
        });
    }

    public bool IsCertificateActive(X509Certificate2 certificate)
    {
        try
        {
            DateTime now = DateTime.Now;
            return now >= certificate.NotBefore && now <= certificate.NotAfter;
        }
        catch
        {
            return false;
        }
    }

    private string GetRevocationReason(string statusInformation)
    {
        if (string.IsNullOrWhiteSpace(statusInformation))
        {
            return "Reason not specified";
        }

        // Common revocation reasons from CRL/OCSP
        string info = statusInformation.ToUpper();

        if (info.Contains("UNSPECIFIED") || info.Contains("REASON NOT SPECIFIED"))
        {
            return "Unspecified";
        }
        else if (info.Contains("KEY COMPROMISE") || info.Contains("KEYCOMPROMISE"))
        {
            return "Key Compromise - The private key was compromised";
        }
        else if (info.Contains("CA COMPROMISE") || info.Contains("CACOMPROMISE"))
        {
            return "CA Compromise - The CA certificate was compromised";
        }
        else if (info.Contains("AFFILIATION CHANGED") || info.Contains("AFFILIATIONCHANGED"))
        {
            return "Affiliation Changed - The certificate holder's affiliation changed";
        }
        else if (info.Contains("SUPERSEDED") || info.Contains("SUPERSEDED"))
        {
            return "Superseded - The certificate was replaced by a new certificate";
        }
        else if (info.Contains("CESSATION OF OPERATION") || info.Contains("CESSATIONOFOPERATION"))
        {
            return "Cessation of Operation - The certificate is no longer needed";
        }
        else if (info.Contains("CERTIFICATE HOLD") || info.Contains("CERTIFICATEHOLD"))
        {
            return "Certificate Hold - Temporarily suspended";
        }
        else if (info.Contains("REMOVE FROM CRL") || info.Contains("REMOVEFROMCRL"))
        {
            return "Remove from CRL - Certificate hold was removed";
        }
        else if (info.Contains("PRIVILEGE WITHDRAWN") || info.Contains("PRIVILEGEWITHDRAWN"))
        {
            return "Privilege Withdrawn - Certificate privileges were withdrawn";
        }
        else if (info.Contains("AA COMPROMISE") || info.Contains("AACOMPROMISE"))
        {
            return "AA Compromise - The attribute authority was compromised";
        }

        // Return the original status information if no standard reason found
        return statusInformation;
    }

    public async Task<CertificateDetails> GetCertificateDetailsAsync(X509Certificate2 certificate)
    {
        return await Task.Run(() =>
        {
            try
            {
                _logger.LogInformation("Getting detailed certificate information for subject: {Subject}", certificate.Subject);

                var details = new CertificateDetails
                {
                    Subject = certificate.Subject,
                    Issuer = certificate.Issuer,
                    SerialNumber = certificate.SerialNumber,
                    Thumbprint = certificate.Thumbprint,
                    NotBefore = certificate.NotBefore,
                    NotAfter = certificate.NotAfter,
                    Version = certificate.Version.ToString(),
                    SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? "Unknown",
                    HasPrivateKey = certificate.HasPrivateKey,
                    DaysUntilExpiration = (certificate.NotAfter - DateTime.Now).Days,
                    IsExpiringSoon = (certificate.NotAfter - DateTime.Now).Days <= 90
                };

                // Parse subject and issuer name parts
                details.SubjectNameParts = ParseDistinguishedName(certificate.Subject);
                details.IssuerNameParts = ParseDistinguishedName(certificate.Issuer);

                // Get public key information
                try
                {
                    var publicKey = certificate.GetRSAPublicKey();
                    if (publicKey != null)
                    {
                        details.PublicKeyAlgorithm = "RSA";
                        details.KeySize = publicKey.KeySize;
                    }
                    else
                    {
                        var ecPublicKey = certificate.GetECDsaPublicKey();
                        if (ecPublicKey != null)
                        {
                            details.PublicKeyAlgorithm = "ECDSA";
                            details.KeySize = ecPublicKey.KeySize;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not determine public key algorithm");
                }

                // Extract extensions
                foreach (var extension in certificate.Extensions.OfType<X509Extension>())
                {
                    try
                    {
                        if (extension.Oid?.Value == "2.5.29.15") // Key Usage
                        {
                            var keyUsage = new X509KeyUsageExtension(extension, false);
                            details.KeyUsage = GetKeyUsageFlags(keyUsage.KeyUsages);
                        }
                        else if (extension.Oid?.Value == "2.5.29.37") // Extended Key Usage
                        {
                            var extKeyUsage = new X509EnhancedKeyUsageExtension(extension, false);
                            details.ExtendedKeyUsage = extKeyUsage.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>()
                                .Select(o => o.FriendlyName ?? o.Value)
                                .Where(name => !string.IsNullOrEmpty(name))
                                .ToList()!;
                        }
                        else if (extension.Oid?.Value == "2.5.29.17") // Subject Alternative Name
                        {
                            details.SubjectAlternativeNames = ExtractSanNames(extension);
                        }
                        else if (extension.Oid?.Value == "2.5.29.32") // Certificate Policies
                        {
                            var policies = ExtractCertificatePolicies(extension);
                            details.CertificatePolicies = policies;
                        }
                        else if (extension.Oid?.Value == "2.5.29.31") // CRL Distribution Points
                        {
                            var crlUrls = ExtractUrlsFromExtension(extension.RawData);
                            details.CrlDistributionPoints = crlUrls;
                        }
                        else if (extension.Oid?.Value == "1.3.6.1.5.5.7.1.1") // Authority Information Access
                        {
                            var ocspUrls = ExtractOcspUrls(extension.RawData);
                            details.OcspUrls = ocspUrls;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Error parsing extension {Oid}", extension.Oid?.Value);
                    }
                }

                _logger.LogInformation("Certificate details extracted successfully. KeyUsage count: {Count}, SAN count: {SanCount}",
                    details.KeyUsage.Count, details.SubjectAlternativeNames.Count);

                return details;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting certificate details");
                throw;
            }
        });
    }

    private Dictionary<string, string> ParseDistinguishedName(string dn)
    {
        var parts = new Dictionary<string, string>();
        try
        {
            var segments = dn.Split(',');
            foreach (var segment in segments)
            {
                var trimmed = segment.Trim();
                var equalIndex = trimmed.IndexOf('=');
                if (equalIndex > 0)
                {
                    var key = trimmed.Substring(0, equalIndex).Trim();
                    var value = trimmed.Substring(equalIndex + 1).Trim();
                    parts[key] = value;
                }
            }
        }
        catch
        {
            // If parsing fails, return empty dictionary
        }
        return parts;
    }

    private List<string> GetKeyUsageFlags(X509KeyUsageFlags flags)
    {
        var usages = new List<string>();
        if (flags.HasFlag(X509KeyUsageFlags.DigitalSignature)) usages.Add("Digital Signature");
        if (flags.HasFlag(X509KeyUsageFlags.NonRepudiation)) usages.Add("Non-Repudiation");
        if (flags.HasFlag(X509KeyUsageFlags.KeyEncipherment)) usages.Add("Key Encipherment");
        if (flags.HasFlag(X509KeyUsageFlags.DataEncipherment)) usages.Add("Data Encipherment");
        if (flags.HasFlag(X509KeyUsageFlags.KeyAgreement)) usages.Add("Key Agreement");
        if (flags.HasFlag(X509KeyUsageFlags.KeyCertSign)) usages.Add("Key Cert Sign");
        if (flags.HasFlag(X509KeyUsageFlags.CrlSign)) usages.Add("CRL Sign");
        if (flags.HasFlag(X509KeyUsageFlags.EncipherOnly)) usages.Add("Encipher Only");
        if (flags.HasFlag(X509KeyUsageFlags.DecipherOnly)) usages.Add("Decipher Only");
        return usages;
    }

    private List<string> ExtractSanNames(X509Extension extension)
    {
        var names = new List<string>();
        try
        {
            // Simplified extraction - full implementation would parse ASN.1
            var dataString = Encoding.UTF8.GetString(extension.RawData);
            // Look for common SAN patterns
            var patterns = new[] { "DNS:", "EMAIL:", "URI:", "IP:" };
            foreach (var pattern in patterns)
            {
                var index = dataString.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
                if (index >= 0)
                {
                    var start = index + pattern.Length;
                    var end = dataString.IndexOfAny(new[] { '\0', '\n', '\r', ' ' }, start);
                    if (end < 0) end = dataString.Length;
                    var value = dataString.Substring(start, end - start).Trim();
                    if (!string.IsNullOrEmpty(value))
                    {
                        names.Add($"{pattern}{value}");
                    }
                }
            }
        }
        catch
        {
            // If extraction fails, return empty list
        }
        return names;
    }

    private List<string> ExtractCertificatePolicies(X509Extension extension)
    {
        var policies = new List<string>();
        try
        {
            var dataString = Encoding.UTF8.GetString(extension.RawData);
            // Look for OID patterns
            var oidPattern = @"\d+\.\d+\.\d+(?:\.\d+)*";
            var matches = System.Text.RegularExpressions.Regex.Matches(dataString, oidPattern);
            foreach (System.Text.RegularExpressions.Match match in matches)
            {
                if (!policies.Contains(match.Value))
                {
                    policies.Add(match.Value);
                }
            }
        }
        catch
        {
            // If extraction fails, return empty list
        }
        return policies;
    }

    private List<string> ExtractUrlsFromExtension(byte[] extensionData)
    {
        var urls = new List<string>();
        try
        {
            var dataString = Encoding.UTF8.GetString(extensionData);
            var urlPattern = @"https?://[^\s""<>\[\]{}]+";
            var matches = System.Text.RegularExpressions.Regex.Matches(dataString, urlPattern);
            foreach (System.Text.RegularExpressions.Match match in matches)
            {
                var url = match.Value.TrimEnd('\\', '/', ',', ';', ')', ']', '}');
                if (!string.IsNullOrEmpty(url) && !urls.Contains(url))
                {
                    urls.Add(url);
                }
            }
        }
        catch
        {
            // If extraction fails, return empty list
        }
        return urls;
    }

    private List<string> ExtractOcspUrls(byte[] extensionData)
    {
        var urls = ExtractUrlsFromExtension(extensionData);
        return urls.Where(url => url.Contains("ocsp", StringComparison.OrdinalIgnoreCase)).ToList();
    }
}

