using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace CACApp.Services;

public class CertificateStorageService : ICertificateStorageService
{
    private readonly string _storagePath;
    private const string STORAGE_FILE = "stored_certificates.json";

    public CertificateStorageService()
    {
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _storagePath = Path.Combine(appDataPath, "CACApp");
        Directory.CreateDirectory(_storagePath);
    }

    public async Task<bool> StoreCertificateAsync(X509Certificate2 certificate)
    {
        try
        {
            var storedCerts = await GetStoredCertificatesAsync();

            var storedCert = new StoredCertificate
            {
                Thumbprint = certificate.Thumbprint,
                Subject = certificate.Subject,
                Issuer = certificate.Issuer,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                StoredDate = DateTime.Now,
                IsActive = DateTime.Now >= certificate.NotBefore && DateTime.Now <= certificate.NotAfter
            };

            var existing = storedCerts.FirstOrDefault(c => c.Thumbprint == certificate.Thumbprint);
            if (existing == null)
            {
                storedCerts.Add(storedCert);
            }
            else
            {
                var index = storedCerts.IndexOf(existing);
                storedCerts[index] = storedCert;
            }

            var json = JsonSerializer.Serialize(storedCerts, new JsonSerializerOptions { WriteIndented = true });
            var filePath = Path.Combine(_storagePath, STORAGE_FILE);
            await File.WriteAllTextAsync(filePath, json);

            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<List<StoredCertificate>> GetStoredCertificatesAsync()
    {
        try
        {
            var filePath = Path.Combine(_storagePath, STORAGE_FILE);
            if (!File.Exists(filePath))
            {
                return new List<StoredCertificate>();
            }

            var json = await File.ReadAllTextAsync(filePath);
            var certificates = JsonSerializer.Deserialize<List<StoredCertificate>>(json);

            if (certificates == null)
            {
                return new List<StoredCertificate>();
            }

            foreach (var cert in certificates)
            {
                cert.IsActive = DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter;
                cert.DaysUntilExpiration = (cert.NotAfter - DateTime.Now).Days;
            }

            return certificates;
        }
        catch
        {
            return new List<StoredCertificate>();
        }
    }

    public async Task<bool> DeleteCertificateAsync(string thumbprint)
    {
        try
        {
            var storedCerts = await GetStoredCertificatesAsync();
            storedCerts.RemoveAll(c => c.Thumbprint == thumbprint);

            var json = JsonSerializer.Serialize(storedCerts, new JsonSerializerOptions { WriteIndented = true });
            var filePath = Path.Combine(_storagePath, STORAGE_FILE);
            await File.WriteAllTextAsync(filePath, json);

            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<List<StoredCertificate>> SearchCertificatesAsync(CertificateSearchCriteria criteria)
    {
        var allCerts = await GetStoredCertificatesAsync();

        return allCerts.Where(cert =>
        {
            // Search text filter
            if (!string.IsNullOrWhiteSpace(criteria.SearchText))
            {
                var searchLower = criteria.SearchText.ToLowerInvariant();
                if (!cert.Subject.ToLowerInvariant().Contains(searchLower) &&
                    !cert.Issuer.ToLowerInvariant().Contains(searchLower) &&
                    !cert.Thumbprint.ToLowerInvariant().Contains(searchLower))
                {
                    return false;
                }
            }

            // Category filter
            if (!string.IsNullOrWhiteSpace(criteria.Category))
            {
                var subjectUpper = cert.Subject.ToUpperInvariant();
                var issuerUpper = cert.Issuer.ToUpperInvariant();
                var categoryUpper = criteria.Category.ToUpperInvariant();

                bool matchesCategory = false;
                if (categoryUpper == "MILITARY" && (subjectUpper.Contains("MIL") || issuerUpper.Contains("MIL")))
                    matchesCategory = true;
                else if (categoryUpper == "GOVERNMENT" && (subjectUpper.Contains("GOV") || issuerUpper.Contains("GOV")))
                    matchesCategory = true;
                else if (categoryUpper == "CONTRACTOR" && (subjectUpper.Contains("CONTRACTOR") || issuerUpper.Contains("CONTRACTOR")))
                    matchesCategory = true;
                else if (categoryUpper == "DOD" && (subjectUpper.Contains("DOD") || issuerUpper.Contains("DOD")))
                    matchesCategory = true;

                if (!matchesCategory) return false;
            }

            // Active filter
            if (criteria.IsActive.HasValue && cert.IsActive != criteria.IsActive.Value)
            {
                return false;
            }

            // Expiration date filters
            if (criteria.ExpiresBefore.HasValue && cert.NotAfter > criteria.ExpiresBefore.Value)
            {
                return false;
            }

            if (criteria.ExpiresAfter.HasValue && cert.NotAfter < criteria.ExpiresAfter.Value)
            {
                return false;
            }

            // Days until expiration filter
            if (criteria.DaysUntilExpiration.HasValue)
            {
                if (cert.DaysUntilExpiration > criteria.DaysUntilExpiration.Value)
                {
                    return false;
                }
            }

            // Expiring soon filter (within 90 days)
            if (criteria.ExpiringSoon.HasValue)
            {
                bool isExpiringSoon = cert.DaysUntilExpiration <= 90 && cert.DaysUntilExpiration >= 0;
                if (isExpiringSoon != criteria.ExpiringSoon.Value)
                {
                    return false;
                }
            }

            return true;
        }).ToList();
    }

    public async Task<List<StoredCertificate>> GetExpiringCertificatesAsync(int daysThreshold)
    {
        var allCerts = await GetStoredCertificatesAsync();
        var now = DateTime.Now;

        return allCerts.Where(cert =>
        {
            var daysUntilExpiration = (cert.NotAfter - now).Days;
            return daysUntilExpiration >= 0 && daysUntilExpiration <= daysThreshold;
        })
        .OrderBy(cert => cert.NotAfter)
        .ToList();
    }
}

