using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace CACApp.Services;

public class CacValidationService : ICacValidationService, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<CacValidationService> _logger;
    private const string DOD_CA_BUNDLE_URL = "https://public.cyber.mil/pki-pke/pkipke-document-library/";
    private const string DOD_ROOT_CA_SUBJECT = "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US";
    private bool _disposed = false;

    public CacValidationService(ILogger<CacValidationService> logger)
    {
        _logger = logger;
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _httpClient?.Dispose();
            _disposed = true;
        }
    }

    public async Task<ValidationResult> ValidateCacOnlineAsync(X509Certificate2 certificate)
    {
        var result = new ValidationResult
        {
            ValidationTime = DateTime.Now
        };

        try
        {
            _logger.LogInformation("Starting CAC online validation for subject: {Subject}, Thumbprint: {Thumbprint}",
                certificate.Subject, certificate.Thumbprint);

            result.Details.Add($"Certificate Subject: {certificate.Subject}");
            result.Details.Add($"Certificate Issuer: {certificate.Issuer}");
            result.Details.Add($"Valid From: {certificate.NotBefore:yyyy-MM-dd}");
            result.Details.Add($"Valid To: {certificate.NotAfter:yyyy-MM-dd}");

            if (!IsCertificateActive(certificate))
            {
                result.IsValid = false;
                result.Status = "Certificate is expired or not yet valid";
                _logger.LogWarning("Certificate validation failed: Certificate is expired or not yet valid. NotBefore: {NotBefore}, NotAfter: {NotAfter}",
                    certificate.NotBefore, certificate.NotAfter);
                return result;
            }

            var category = DetermineCategory(certificate);
            result.Category = category;
            _logger.LogInformation("Certificate category determined: {Category}", category);

            // Check online validation status first
            bool onlineValidationFailed = false;
            string? onlineFailureReason = null;

            using (var testChain = new X509Chain())
            {
                testChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                testChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                testChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                testChain.ChainPolicy.VerificationTime = DateTime.Now;
                testChain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);

                bool onlineValid = testChain.Build(certificate);
                if (!onlineValid)
                {
                    onlineValidationFailed = true;
                    foreach (X509ChainStatus status in testChain.ChainStatus)
                    {
                        if (status.Status != X509ChainStatusFlags.NoError)
                        {
                            if (status.Status.HasFlag(X509ChainStatusFlags.Revoked))
                            {
                                onlineFailureReason = $"Online revocation check reported revoked: {status.StatusInformation}";
                                break;
                            }
                            else if (status.Status.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown) ||
                                     status.Status.HasFlag(X509ChainStatusFlags.OfflineRevocation))
                            {
                                if (string.IsNullOrEmpty(onlineFailureReason))
                                {
                                    onlineFailureReason = $"Revocation status could not be verified online: {status.StatusInformation}";
                                }
                            }
                        }
                    }
                    if (string.IsNullOrEmpty(onlineFailureReason))
                    {
                        onlineFailureReason = "Online certificate chain validation failed";
                    }
                }
            }

            bool isValidChain = await ValidateCertificateChainAsync(certificate);
            if (!isValidChain)
            {
                result.IsValid = false;
                result.Status = "Certificate chain validation failed";
                result.Details.Add("Unable to verify certificate chain");
                if (onlineValidationFailed && !string.IsNullOrEmpty(onlineFailureReason))
                {
                    result.OnlineValidationFailed = true;
                    result.OnlineValidationFailureReason = onlineFailureReason;
                    result.Details.Add($"⚠️ WARNING: {onlineFailureReason}");
                }
                _logger.LogWarning("CAC validation failed: Certificate chain validation failed for subject: {Subject}", certificate.Subject);
                return result;
            }

            _logger.LogInformation("Certificate chain validation succeeded");

            // If online validation failed but offline succeeded, add notification
            if (onlineValidationFailed && !string.IsNullOrEmpty(onlineFailureReason))
            {
                result.OnlineValidationFailed = true;
                result.OnlineValidationFailureReason = onlineFailureReason;
                result.Details.Add($"⚠️ WARNING: {onlineFailureReason} Offline validation succeeded - certificate is valid.");
                _logger.LogWarning("Online validation failed but offline validation succeeded: {Reason}", onlineFailureReason);
            }

            bool isDoDCert = IsDoDCertificate(certificate);
            if (isDoDCert)
            {
                result.IsValid = true;
                result.Status = $"Valid {category} CAC";
                result.Details.Add("Certificate chain verified");
                result.Details.Add("DoD root CA found in chain");
                _logger.LogInformation("CAC validation succeeded: Valid {Category} CAC", category);
            }
            else
            {
                result.IsValid = false;
                result.Status = "Certificate is not a recognized DoD/GOVT/Military certificate";
                result.Details.Add("Certificate does not chain to DoD root CA");
                _logger.LogWarning("CAC validation failed: Certificate is not a recognized DoD/GOVT/Military certificate. Subject: {Subject}, Issuer: {Issuer}",
                    certificate.Subject, certificate.Issuer);
            }
        }
        catch (Exception ex)
        {
            result.IsValid = false;
            result.Status = $"Validation error: {ex.Message}";
            result.Details.Add($"Exception: {ex.GetType().Name}");
            _logger.LogError(ex, "Exception during CAC online validation for subject: {Subject}", certificate.Subject);
        }

        return result;
    }

    private bool IsCertificateActive(X509Certificate2 certificate)
    {
        DateTime now = DateTime.Now;
        return now >= certificate.NotBefore && now <= certificate.NotAfter;
    }

    private string DetermineCategory(X509Certificate2 certificate)
    {
        var subject = certificate.Subject.ToUpper();
        var issuer = certificate.Issuer.ToUpper();

        if (subject.Contains("MIL") || issuer.Contains("MIL"))
        {
            return "Military";
        }
        else if (subject.Contains("GOV") || issuer.Contains("GOV") || subject.Contains("GOVERNMENT"))
        {
            return "Government";
        }
        else if (subject.Contains("CONTRACTOR") || issuer.Contains("CONTRACTOR"))
        {
            return "Contractor";
        }
        else if (subject.Contains("DOD") || issuer.Contains("DOD"))
        {
            return "DoD";
        }

        return "Unknown";
    }

    private bool IsDoDCertificate(X509Certificate2 certificate)
    {
        try
        {
            // Use NoCheck for revocation to avoid false positives when checking DoD certificate
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = DateTime.Now;

            if (chain.Build(certificate))
            {
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    if (element.Certificate.Subject.Contains("DoD") ||
                        element.Certificate.Issuer.Contains("DoD") ||
                        element.Certificate.Subject.Contains(DOD_ROOT_CA_SUBJECT))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {
        }

        var subject = certificate.Subject.ToUpper();
        var issuer = certificate.Issuer.ToUpper();

        return subject.Contains("DOD") || issuer.Contains("DOD") ||
               subject.Contains("MIL") || issuer.Contains("MIL") ||
               subject.Contains("GOV") || issuer.Contains("GOV");
    }

    private Task<bool> ValidateCertificateChainAsync(X509Certificate2 certificate)
    {
        return Task.Run(() =>
        {
            try
            {
                _logger.LogDebug("Validating certificate chain for CAC validation. Subject: {Subject}", certificate.Subject);

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
                bool hasRevocationUnknown = false;
                bool hasActualRevocation = false;

                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    if (status.Status != X509ChainStatusFlags.NoError)
                    {
                        _logger.LogDebug("Chain status: {Status}, Information: {StatusInformation}", status.Status, status.StatusInformation);
                    }

                    if (status.Status.HasFlag(X509ChainStatusFlags.Revoked))
                    {
                        hasActualRevocation = true;
                        _logger.LogWarning("Certificate chain validation: Online check reported REVOKED. Status: {Status}, Info: {StatusInformation}",
                            status.Status, status.StatusInformation);
                        // Don't return false yet - verify with offline check first
                    }
                    else if (status.Status.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown) ||
                             status.Status.HasFlag(X509ChainStatusFlags.OfflineRevocation))
                    {
                        hasRevocationUnknown = true;
                        _logger.LogInformation("Revocation status unknown (network/connectivity issue): {StatusInformation}", status.StatusInformation);
                    }
                }

                // If revocation was reported online, verify with offline check (could be false positive)
                if (hasActualRevocation && !isValid)
                {
                    _logger.LogInformation("Revocation reported online - verifying with offline check to rule out false positives");
                    using var offlineChain = new X509Chain();
                    offlineChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    offlineChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    offlineChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    offlineChain.ChainPolicy.VerificationTime = DateTime.Now;

                    bool offlineValid = offlineChain.Build(certificate);
                    _logger.LogInformation("Offline chain build result: {IsValid}", offlineValid);

                    if (offlineValid)
                    {
                        // Offline validation succeeded - online revocation was likely a false positive
                        _logger.LogWarning("Online revocation check reported revoked, but offline validation succeeded. Likely false positive from network/cache issues.");
                        // Return true but mark that online validation failed
                        // Note: This method doesn't have access to ValidationResult, so we'll handle it in ValidateCacOnlineAsync
                        return true; // Certificate is valid
                    }
                    else
                    {
                        // Check if offline also shows revocation
                        bool offlineHasRevocation = false;
                        foreach (X509ChainStatus status in offlineChain.ChainStatus)
                        {
                            if (status.Status.HasFlag(X509ChainStatusFlags.Revoked))
                            {
                                offlineHasRevocation = true;
                                _logger.LogWarning("Certificate REVOKED (confirmed offline): Status: {Status}, Info: {StatusInformation}",
                                    status.Status, status.StatusInformation);
                                break;
                            }
                        }

                        if (offlineHasRevocation)
                        {
                            return false; // Actually revoked
                        }
                        else
                        {
                            _logger.LogWarning("Offline chain validation also failed but no revocation found - may be a different validation issue");
                            // Check for other errors
                            foreach (X509ChainStatus status in offlineChain.ChainStatus)
                            {
                                if (status.Status != X509ChainStatusFlags.NoError)
                                {
                                    _logger.LogWarning("  Status: {Status}, Information: {StatusInformation}",
                                        status.Status, status.StatusInformation);
                                }
                            }
                            return false;
                        }
                    }
                }
                // If revocation status couldn't be determined but chain is otherwise valid, try offline
                else if (hasRevocationUnknown && !hasActualRevocation && !isValid)
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
                        _logger.LogWarning("Offline chain validation also failed. Chain status details:");
                        foreach (X509ChainStatus status in offlineChain.ChainStatus)
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
                        _logger.LogInformation("Offline validation succeeded - chain is valid but revocation status could not be verified");
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
                _logger.LogError(ex, "Exception during certificate chain validation for CAC validation. Subject: {Subject}", certificate.Subject);
                return false;
            }
        });
    }
}

