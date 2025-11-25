using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace CACApp.Services;

public class CertificateExportService : ICertificateExportService
{
    private readonly ILogger<CertificateExportService> _logger;

    public CertificateExportService(ILogger<CertificateExportService> logger)
    {
        _logger = logger;
    }

    public async Task<CertificateExportResult> ExportCertificateAsync(X509Certificate2 certificate, CertificateExportFormat format, string? password = null)
    {
        return await Task.Run(() =>
        {
            try
            {
                _logger.LogInformation("Exporting certificate {Thumbprint} in format {Format}", certificate.Thumbprint, format);

                byte[] data;
                string fileName;
                string mimeType;

                switch (format)
                {
                    case CertificateExportFormat.Pem:
                        var pem = certificate.ExportCertificatePem();
                        data = Encoding.UTF8.GetBytes(pem);
                        fileName = $"certificate_{certificate.Thumbprint}.pem";
                        mimeType = "application/x-pem-file";
                        break;

                    case CertificateExportFormat.Der:
                        data = certificate.Export(X509ContentType.Cert);
                        fileName = $"certificate_{certificate.Thumbprint}.der";
                        mimeType = "application/x-x509-ca-cert";
                        break;

                    case CertificateExportFormat.Pfx:
                        if (string.IsNullOrEmpty(password))
                        {
                            throw new ArgumentException("Password is required for PFX export");
                        }
                        if (!certificate.HasPrivateKey)
                        {
                            throw new InvalidOperationException("Certificate does not have a private key. PFX export requires a private key.");
                        }
                        try
                        {
                            data = certificate.Export(X509ContentType.Pkcs12, password);
                        }
                        catch (CryptographicException ex)
                        {
                            if (ex.Message.Contains("not exportable") || ex.Message.Contains("private key"))
                            {
                                throw new InvalidOperationException("The private key is not exportable. Smart card private keys cannot be exported.", ex);
                            }
                            throw;
                        }
                        fileName = $"certificate_{certificate.Thumbprint}.pfx";
                        mimeType = "application/x-pkcs12";
                        break;

                    default:
                        throw new ArgumentException($"Unsupported export format: {format}");
                }

                _logger.LogInformation("Certificate exported successfully. Size: {Size} bytes", data.Length);

                return new CertificateExportResult
                {
                    Data = data,
                    FileName = fileName,
                    MimeType = mimeType
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exporting certificate");
                throw;
            }
        });
    }

    public async Task<X509Certificate2?> ImportCertificateAsync(byte[] certificateData, CertificateImportFormat format, string? password = null)
    {
        return await Task.Run(() =>
        {
            try
            {
                _logger.LogInformation("Importing certificate in format {Format}", format);

                X509Certificate2? certificate = null;

                switch (format)
                {
                    case CertificateImportFormat.Pem:
                        var pemString = Encoding.UTF8.GetString(certificateData);
                        certificate = X509Certificate2.CreateFromPem(pemString);
                        break;

                    case CertificateImportFormat.Der:
#pragma warning disable SYSLIB0057
                        certificate = new X509Certificate2(certificateData);
#pragma warning restore SYSLIB0057
                        break;

                    case CertificateImportFormat.Pfx:
#pragma warning disable SYSLIB0057
                        if (string.IsNullOrEmpty(password))
                        {
                            certificate = new X509Certificate2(certificateData);
                        }
                        else
                        {
                            certificate = new X509Certificate2(certificateData, password);
                        }
#pragma warning restore SYSLIB0057
                        break;

                    default:
                        throw new ArgumentException($"Unsupported import format: {format}");
                }

                if (certificate != null)
                {
                    _logger.LogInformation("Certificate imported successfully. Subject: {Subject}, Thumbprint: {Thumbprint}",
                        certificate.Subject, certificate.Thumbprint);
                }

                return certificate;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error importing certificate");
                return null;
            }
        });
    }
}

