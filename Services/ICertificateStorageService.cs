using System.Security.Cryptography.X509Certificates;

namespace CACApp.Services;

public interface ICertificateStorageService
{
    Task<bool> StoreCertificateAsync(X509Certificate2 certificate);
    Task<List<StoredCertificate>> GetStoredCertificatesAsync();
    Task<List<StoredCertificate>> SearchCertificatesAsync(CertificateSearchCriteria criteria);
    Task<bool> DeleteCertificateAsync(string thumbprint);
    Task<List<StoredCertificate>> GetExpiringCertificatesAsync(int daysThreshold);
}

public class StoredCertificate
{
    public string Thumbprint { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public DateTime StoredDate { get; set; }
    public bool IsActive { get; set; }
    public int DaysUntilExpiration { get; set; }
}

public class CertificateSearchCriteria
{
    public string? SearchText { get; set; }
    public string? Category { get; set; } // "Military", "Government", "Contractor", etc.
    public bool? IsActive { get; set; }
    public DateTime? ExpiresBefore { get; set; }
    public DateTime? ExpiresAfter { get; set; }
    public int? DaysUntilExpiration { get; set; }
    public bool? ExpiringSoon { get; set; } // Within 90 days
}

