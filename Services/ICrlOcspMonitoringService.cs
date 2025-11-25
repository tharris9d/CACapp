using System.Security.Cryptography.X509Certificates;

namespace CACApp.Services;

public interface ICrlOcspMonitoringService
{
    Task<CrlOcspStatus> CheckCertificateRevocationStatusAsync(X509Certificate2 certificate);
    Task<CrlStatus> CheckCrlStatusAsync(string crlUrl);
    Task<OcspStatus> CheckOcspStatusAsync(string ocspUrl, X509Certificate2 certificate);
    Task<List<RevocationDistributionPoint>> GetRevocationDistributionPointsAsync(X509Certificate2 certificate);
}

public class CrlOcspStatus
{
    public bool IsAvailable { get; set; }
    public string RevocationStatus { get; set; } = "Not Available"; // "Revoked", "Not Available", "Valid"
    public List<CrlStatus> CrlStatuses { get; set; } = new();
    public List<OcspStatus> OcspStatuses { get; set; } = new();
    public DateTime CheckTime { get; set; } = DateTime.Now;
    public string? ErrorMessage { get; set; }
}

public class CrlStatus
{
    public string Url { get; set; } = string.Empty;
    public bool IsAccessible { get; set; }
    public TimeSpan? ResponseTime { get; set; }
    public DateTime? LastUpdate { get; set; }
    public DateTime? NextUpdate { get; set; }
    public int? RevokedCertificateCount { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CheckTime { get; set; } = DateTime.Now;
}

public class OcspStatus
{
    public string Url { get; set; } = string.Empty;
    public bool IsAccessible { get; set; }
    public TimeSpan? ResponseTime { get; set; }
    public string? ResponseStatus { get; set; }
    public bool? IsRevoked { get; set; }
    public DateTime? ThisUpdate { get; set; }
    public DateTime? NextUpdate { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CheckTime { get; set; } = DateTime.Now;
}

public class RevocationDistributionPoint
{
    public string Type { get; set; } = string.Empty; // "CRL" or "OCSP"
    public string Url { get; set; } = string.Empty;
    public string? Description { get; set; }
}



