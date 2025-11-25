using System.Security.Cryptography.X509Certificates;

namespace CACApp.Services;

public interface ICertificateExportService
{
    Task<CertificateExportResult> ExportCertificateAsync(X509Certificate2 certificate, CertificateExportFormat format, string? password = null);
    Task<X509Certificate2?> ImportCertificateAsync(byte[] certificateData, CertificateImportFormat format, string? password = null);
}

public enum CertificateExportFormat
{
    Pem,
    Der,
    Pfx
}

public enum CertificateImportFormat
{
    Pem,
    Der,
    Pfx
}

public class CertificateExportResult
{
    public byte[] Data { get; set; } = Array.Empty<byte>();
    public string FileName { get; set; } = string.Empty;
    public string MimeType { get; set; } = string.Empty;
}


