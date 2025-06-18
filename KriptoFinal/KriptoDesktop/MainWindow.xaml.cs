using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using Microsoft.Win32;

namespace KriptoDesktop;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private string selectedFilePath = string.Empty;

    public MainWindow()
    {
        InitializeComponent();
    }

    // RSA Anahtar Üretimi
    private void btnGenerateKeys_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            using var rsa = RSA.Create(2048);

            var publicKey = rsa.ExportRSAPublicKey();
            var privateKey = rsa.ExportRSAPrivateKey();

            string publicKeyString = Convert.ToBase64String(publicKey);
            string privateKeyString = Convert.ToBase64String(privateKey);

            txtPublicKey.Text = publicKeyString;
            txtPrivateKey.Text = privateKeyString;

            MessageBox.Show("RSA anahtar çifti başarıyla oluşturuldu!", "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Anahtar oluşturma hatası: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void btnCopyPublic_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(txtPublicKey.Text))
        {
            Clipboard.SetText(txtPublicKey.Text);
            MessageBox.Show("Public key panoya kopyalandı!", "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void btnCopyPrivate_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(txtPrivateKey.Text))
        {
            Clipboard.SetText(txtPrivateKey.Text);
            MessageBox.Show("Private key panoya kopyalandı!", "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    // RSA Şifreleme
    private void btnEncrypt_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(txtEncryptPublicKey.Text))
            {
                MessageBox.Show("Lütfen public key girin.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (string.IsNullOrWhiteSpace(txtPlainText.Text))
            {
                MessageBox.Show("Lütfen şifrelenecek metni girin.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            byte[] publicKeyBytes = Convert.FromBase64String(txtEncryptPublicKey.Text);

            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(publicKeyBytes, out _);

            var data = Encoding.UTF8.GetBytes(txtPlainText.Text);
            var encryptedBytes = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);

            string encryptedText = Convert.ToBase64String(encryptedBytes);
            txtEncryptedText.Text = encryptedText;

            MessageBox.Show("Metin başarıyla şifrelendi!", "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Şifreleme hatası: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // RSA Şifre Çözme
    private void btnDecrypt_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(txtDecryptPrivateKey.Text))
            {
                MessageBox.Show("Lütfen private key girin.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (string.IsNullOrWhiteSpace(txtEncryptedTextToDecrypt.Text))
            {
                MessageBox.Show("Lütfen şifrelenmiş metni girin.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            byte[] privateKeyBytes = Convert.FromBase64String(txtDecryptPrivateKey.Text);
            byte[] encryptedBytes = Convert.FromBase64String(txtEncryptedTextToDecrypt.Text);

            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

            var decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
            string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            txtDecryptedText.Text = decryptedText;

            MessageBox.Show("Metin başarıyla çözüldü!", "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Şifre çözme hatası: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // SHA-256 Hash
    private void rbText_Checked(object sender, RoutedEventArgs e)
    {
        if (txtHashInput == null || btnSelectFile == null)
            return;
        txtHashInput.IsEnabled = true;
        btnSelectFile.Visibility = Visibility.Collapsed;
        txtHashInput.Text = string.Empty;
    }

    private void rbFile_Checked(object sender, RoutedEventArgs e)
    {
        if (txtHashInput == null || btnSelectFile == null)
            return;
        txtHashInput.IsEnabled = false;
        btnSelectFile.Visibility = Visibility.Visible;
        txtHashInput.Text = string.Empty;
    }

    private void btnSelectFile_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog();
        openFileDialog.Title = "Hash hesaplanacak dosyayı seçin";
        openFileDialog.Filter = "Tüm dosyalar (*.*)|*.*";

        if (openFileDialog.ShowDialog() == true)
        {
            selectedFilePath = openFileDialog.FileName;
            txtHashInput.Text = $"Seçilen dosya: {Path.GetFileName(selectedFilePath)}";
        }
    }

    private void btnCalculateHash_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string hashResult = string.Empty;

            if (rbText.IsChecked == true)
            {
                if (string.IsNullOrWhiteSpace(txtHashInput.Text))
                {
                    MessageBox.Show("Lütfen metin girin.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                hashResult = ComputeSHA256Hash(Encoding.UTF8.GetBytes(txtHashInput.Text));
            }
            else if (rbFile.IsChecked == true)
            {
                if (string.IsNullOrEmpty(selectedFilePath) || !File.Exists(selectedFilePath))
                {
                    MessageBox.Show("Lütfen geçerli bir dosya seçin.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                byte[] fileBytes = File.ReadAllBytes(selectedFilePath);
                hashResult = ComputeSHA256Hash(fileBytes);
            }

            txtHashResult.Text = hashResult;
            MessageBox.Show("Hash başarıyla hesaplandı!", "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Hash hesaplama hatası: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private string ComputeSHA256Hash(byte[] data)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(data);
        var sb = new StringBuilder();
        foreach (var b in hashBytes)
            sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}