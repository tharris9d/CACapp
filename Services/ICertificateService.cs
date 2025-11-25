using System.Security.Cryptography.X509Certificates;

namespace CACApp.Services;

public interface ICertificateService
{
    Task<bool> ValidateCertificateChainAsync(X509Certificate2 certificate);
    Task<CertificateChainInfo> GetChainInfoAsync(X509Certificate2 certificate);
    bool IsCertificateActive(X509Certificate2 certificate);
    Task<CertificateDetails> GetCertificateDetailsAsync(X509Certificate2 certificate);
}

public class CertificateChainInfo
{
    public bool IsValid { get; set; }
    public List<string> ChainErrors { get; set; } = new();
    public List<CertificateInfo> Chain { get; set; } = new();
    public bool OnlineValidationFailed { get; set; }
    public string? OnlineValidationFailureReason { get; set; }
}

public class CertificateInfo
{
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public bool IsValid { get; set; }
    public string Thumbprint { get; set; } = string.Empty;
}

public class CertificateDetails
{
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string Version { get; set; } = string.Empty;
    public string SignatureAlgorithm { get; set; } = string.Empty;
    public string PublicKeyAlgorithm { get; set; } = string.Empty;
    public int KeySize { get; set; }
    public bool HasPrivateKey { get; set; }
    public List<string> KeyUsage { get; set; } = new();
    public List<string> ExtendedKeyUsage { get; set; } = new();
    public List<string> SubjectAlternativeNames { get; set; } = new();
    public List<string> CertificatePolicies { get; set; } = new();
    public List<string> CrlDistributionPoints { get; set; } = new();
    public List<string> OcspUrls { get; set; } = new();
    public Dictionary<string, string> SubjectNameParts { get; set; } = new();
    public Dictionary<string, string> IssuerNameParts { get; set; } = new();
    public int DaysUntilExpiration { get; set; }
    public bool IsExpiringSoon { get; set; }
}

