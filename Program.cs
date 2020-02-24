using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;
using System.Diagnostics;


namespace TestNetAES
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] key16 = new byte[16], nonce = new byte[12];
            RandomNumberGenerator.Fill(key16);
            //RandomNumberGenerator.Fill(nonce);


            GcmBlockCipher bc = new GcmBlockCipher(new AesEngine());
            AesCcm net = new AesCcm(key16);

            byte[] raw = null;

            Stopwatch sw = new Stopwatch();
            Console.WriteLine("1K, 1000轮");
            {
                raw = new byte[1024];
                RandomNumberGenerator.Fill(raw);


                {
                    byte[] cipher = new byte[raw.Length + 1000], tag = new byte[16];
                    sw.Start();
                    for (int i = 0; i < 1000; i++)
                    {
                        nonce = new byte[12];
                        RandomNumberGenerator.Fill(nonce);
                        AeadParameters parameters = new AeadParameters(new KeyParameter(key16), 16 * 8, nonce);
                        bc.Init(true, parameters);
                        var len = bc.ProcessBytes(raw, 0, raw.Length, cipher, 0);
                        bc.DoFinal(cipher, len);
                    }
                    sw.Stop();
                    Console.WriteLine($"BouncyCastle:{ sw.ElapsedMilliseconds}ms");
                    sw.Reset();
                }
                {
                    byte[] cipher = new byte[raw.Length], tag = new byte[16];
                    sw.Start();
                    for (int i = 0; i < 1000; i++)
                    {
                        nonce = new byte[12];
                        RandomNumberGenerator.Fill(nonce);
                        net.Encrypt(nonce, raw, cipher, tag, null);
                    }
                    sw.Stop();
                    Console.WriteLine($"Net:{ sw.ElapsedMilliseconds}ms");
                    sw.Reset();
                }
            }
            Console.WriteLine("======================");
            Console.WriteLine("8K, 1000轮");
            {
                raw = new byte[1024 * 8];
                RandomNumberGenerator.Fill(raw);


                {
                    byte[] cipher = new byte[raw.Length + 1000], tag = new byte[16];
                    sw.Start();
                    for (int i = 0; i < 1000; i++)
                    {
                        nonce = new byte[12];
                        RandomNumberGenerator.Fill(nonce);
                        AeadParameters parameters = new AeadParameters(new KeyParameter(key16), 16 * 8, nonce);
                        bc.Init(true, parameters);
                        var len = bc.ProcessBytes(raw, 0, raw.Length, cipher, 0);
                        bc.DoFinal(cipher, len);
                    }
                    sw.Stop();
                    Console.WriteLine($"BouncyCastle:{ sw.ElapsedMilliseconds}ms");
                    sw.Reset();
                }
                {
                    byte[] cipher = new byte[raw.Length], tag = new byte[16];
                    sw.Start();
                    for (int i = 0; i < 1000; i++)
                    {
                        nonce = new byte[12];
                        RandomNumberGenerator.Fill(nonce);
                        net.Encrypt(nonce, raw, cipher, tag, null);
                    }
                    sw.Stop();
                    Console.WriteLine($"Net:{sw.ElapsedMilliseconds }ms");
                    sw.Reset();
                }
            }

            Console.WriteLine("======================");
            Console.WriteLine("16K, 1000轮");
            {
                raw = new byte[1024 * 16];
                RandomNumberGenerator.Fill(raw);


                {
                    byte[] cipher = new byte[raw.Length + 1000], tag = new byte[16];
                    sw.Start();
                    for (int i = 0; i < 1000; i++)
                    {
                        nonce = new byte[12];
                        RandomNumberGenerator.Fill(nonce);
                        AeadParameters parameters = new AeadParameters(new KeyParameter(key16), 16 * 8, nonce);
                        bc.Init(true, parameters);
                        var len = bc.ProcessBytes(raw, 0, raw.Length, cipher, 0);
                        bc.DoFinal(cipher, len);
                    }
                    sw.Stop();
                    Console.WriteLine($"BouncyCastle:{ sw.ElapsedMilliseconds}ms");
                    sw.Reset();
                }
                {
                    byte[] cipher = new byte[raw.Length], tag = new byte[16];
                    sw.Start();
                    for (int i = 0; i < 1000; i++)
                    {
                        nonce = new byte[12];
                        RandomNumberGenerator.Fill(nonce);
                        net.Encrypt(nonce, raw, cipher, tag, null);
                    }
                    sw.Stop();
                    Console.WriteLine($"Net:{ sw.ElapsedMilliseconds}ms");
                    sw.Reset();
                }
            }
            Console.WriteLine("======================");
            Console.WriteLine("256K, 1000轮");
            {
                raw = new byte[1024 * 256];
                RandomNumberGenerator.Fill(raw);


                {
                    byte[] cipher = new byte[raw.Length + 1000], tag = new byte[16];
                    sw.Start();
                    for (int i = 0; i < 1000; i++)
                    {
                        nonce = new byte[12];
                        RandomNumberGenerator.Fill(nonce);
                        AeadParameters parameters = new AeadParameters(new KeyParameter(key16), 16 * 8, nonce);
                        bc.Init(true, parameters);
                        var len = bc.ProcessBytes(raw, 0, raw.Length, cipher, 0);
                        bc.DoFinal(cipher, len);
                    }
                    sw.Stop();
                    Console.WriteLine($"BouncyCastle:{ sw.ElapsedMilliseconds}ms");
                    sw.Reset();
                }
                {
                    byte[] cipher = new byte[raw.Length], tag = new byte[16];
                    sw.Start();
                    for (int i = 0; i < 1000; i++)
                    {
                        nonce = new byte[12];
                        RandomNumberGenerator.Fill(nonce);
                        net.Encrypt(nonce, raw, cipher, tag, null);
                    }
                    sw.Stop();
                    Console.WriteLine($"Net:{ sw.ElapsedMilliseconds}ms");
                    sw.Reset();
                }
            }





            Console.WriteLine("Hello World!");
            Console.ReadKey();

        }
    }
}
