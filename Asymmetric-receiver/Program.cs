using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Asymmetric_receiver
{
    class Program
    {
        static void Main(string[] args)
        {

            var rsa = new RsaWithXmlKey();

            const string publicKeyPath = "c:\\temp\\publickey.xml";
            const string privateKeyPath = "c:\\temp\\privatekey.xml";

            rsa.AssignNewKey(publicKeyPath, privateKeyPath);

            TcpListener server = null;
            try
            {
                // Set the TcpListener on port 13000.
                Int32 port = 13000;
                IPAddress localAddr = IPAddress.Parse("127.0.0.1");

                // TcpListener server = new TcpListener(port);
                server = new TcpListener(localAddr, port);

                // Start listening for client requests.
                server.Start();

                // Buffer for reading data
                byte[] bytes = new byte[256];
                string data = null;

                // Enter the listening loop.
                while (true)
                {
                    Console.Write("Waiting for a connection... ");

                    // Perform a blocking call to accept requests.
                    // You could also use server.AcceptSocket() here.
                    TcpClient client = server.AcceptTcpClient();
                    Console.WriteLine("Connected!");

                    data = null;

                    // Get a stream object for reading and writing
                    NetworkStream stream = client.GetStream();

                    int i;

                    // Loop to receive all the data sent by the client.
                    while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
                    {
                        // Translate data bytes to a ASCII string.
                        data = Convert.ToBase64String(bytes, 0, i);
                        //Console.WriteLine(data);
                        data = RsaWithXml(rsa, data, privateKeyPath);
                    }

                    // Shutdown and end connection
                    client.Close();
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
            }
            finally
            {
                // Stop listening for new clients.
                server.Stop();
            }



            Console.WriteLine("\nHit enter to continue...");
            Console.Read();
        }

        static string RsaWithXml(RsaWithXmlKey rsa, string msg, string privateKeyPath)
        {
            //var encrypted = rsa.EncryptData(publicKeyPath, Encoding.UTF8.GetBytes(msg));
            Console.WriteLine("Recieved message: {0}", msg);
            try
            {
                using (var r = new RSACryptoServiceProvider(2048))
                {
                    r.PersistKeyInCsp = false;
                    r.FromXmlString(File.ReadAllText(privateKeyPath));
                    RSAParameters parameters = r.ExportParameters(true);
                    var decrypted = rsa.DecryptData(privateKeyPath, Convert.FromBase64String(msg));
                    Console.WriteLine();
                    Console.WriteLine("D - {0}", Convert.ToBase64String(parameters.D));
                    Console.WriteLine("DP - {0}", Convert.ToBase64String(parameters.DP));
                    Console.WriteLine("DQ - {0}", Convert.ToBase64String(parameters.DQ));
                    Console.WriteLine("Inverse Q - {0}", Convert.ToBase64String(parameters.InverseQ));
                    Console.WriteLine("P - {0}", Convert.ToBase64String(parameters.P));
                    Console.WriteLine("Q - {0}", Convert.ToBase64String(parameters.Q));
                    Console.WriteLine("   Decrypted Text = " + Encoding.Default.GetString(decrypted));
                    Console.WriteLine();

                    return Encoding.Default.GetString(decrypted);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("Error happened: {0}", e.Message);
                return "Error";
            }


        }
    }
}

