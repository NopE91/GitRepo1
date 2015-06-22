using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

using System.Security.Cryptography;
using System.IO;

namespace EncryptDecrypt_Pwd
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();            
        }

        private string encryptedText;
        private string decryptedText;
       
        //-- Added From NFS Solution Encryption Method ---//

        private static byte[] _salt = Encoding.ASCII.GetBytes("o6806642kbM7c5");
        private static string _encryptionKey = "Resolve";
 
        // ---- END ---- //


        private void button1_Click(object sender, RoutedEventArgs e)
        {
            txtEnPwd.Text=string.Empty;
            txtDePwd.Text=string.Empty;
            string passwordText = txtPwd.Text.Trim();
            if (passwordText.Count() <= 0)
            {
                MessageBox.Show("Input Length Incorrect", "Infromation", MessageBoxButton.OKCancel, MessageBoxImage.Exclamation);
            }
            else
            {
                encryptedText = AESEncryption(passwordText);
                txtEnPwd.Text = encryptedText;
                MessageBox.Show(encryptedText, "Encypted Password", MessageBoxButton.OK, MessageBoxImage.Information, MessageBoxResult.None);
            }
            
        }

        private void button2_Click(object sender, RoutedEventArgs e)
        {
            string passwordText = txtEnPwd.Text.Trim();
            int stringLength = passwordText.Count();
            if (stringLength == 24)
            {
                txtPwd.Text = string.Empty;
                decryptedText = AESDecryption(passwordText);
                txtDePwd.Text = decryptedText;
                MessageBox.Show(decryptedText, "Decrypted Password", MessageBoxButton.OKCancel);
            }
            else
            {
                MessageBox.Show("Decrypted Password Length Incorrect", "Infromation", MessageBoxButton.OKCancel,MessageBoxImage.Exclamation);
            }
        }

        #region AES Encryption and Descryption

        private string AESEncryption(string dataRequest)
        {
            if (string.IsNullOrEmpty(dataRequest))
                return string.Empty;

            string outputString = null;
            RijndaelManaged aesZah = new RijndaelManaged();

            try
            {
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(_encryptionKey, _salt);
                aesZah.Key = key.GetBytes(aesZah.KeySize / 8);
                aesZah.IV = key.GetBytes(aesZah.BlockSize / 8);

                ICryptoTransform encryptor = aesZah.CreateEncryptor(aesZah.Key, aesZah.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {                            
                            swEncrypt.Write(dataRequest);
                        }
                    }
                    outputString = Convert.ToBase64String(msEncrypt.ToArray());
                }                
            }

            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            } 

            finally
            {
                if (aesZah != null)
                    aesZah.Clear();
                //MessageBox.Show("AES password Encrypted Successfully", "Information", MessageBoxButton.OK);
            }

            return outputString;
        }

        private string AESDecryption(string dataRequest)
        {
            if (string.IsNullOrEmpty(dataRequest))
                return string.Empty;

            string outputString = null;
            RijndaelManaged aesMng = new RijndaelManaged();

            try
            {
                // generate the key from the shared secret and the salt
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(_encryptionKey, _salt);
                // Create a RijndaelManaged object
                // with the specified key and IV.

                aesMng.Key = key.GetBytes(aesMng.KeySize / 8);
                aesMng.IV = key.GetBytes(aesMng.BlockSize / 8);

                ICryptoTransform decryptor = aesMng.CreateDecryptor(aesMng.Key, aesMng.IV);
                byte[] bytes = Convert.FromBase64String(dataRequest);
                using (MemoryStream msDecrypt = new MemoryStream(bytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            outputString = srDecrypt.ReadToEnd();
                    }
                }
            }

            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

            finally
            {
                if (aesMng != null)
                    aesMng.Clear();
                //MessageBox.Show("AES Password Decrypted Successfully", "Information", MessageBoxButton.OK);
            }

            return outputString;
        }

        #endregion

    }
}
