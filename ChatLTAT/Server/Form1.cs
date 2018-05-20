using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Server
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            CheckForIllegalCrossThreadCalls = false;

            Connect();
        }
        MD5 md5 = new MD5();  
        AES aes = new AES();
        IPEndPoint IP;
        Socket client;
        Socket server;
        byte[] khoapublic;
        byte[] khoabimat;
        List<Socket> clientList;
        string keypublic;
        string keysecret;
        string keyclient;
        DiffieHellman diff;
        byte[] nhankey;
        byte[] data;
        byte[] tinnhan;
        byte[] nhankeydadoi;
        string dateTimeIV;
        byte[] dateTimeIv;

        void Connect()
        {
            clientList = new List<Socket>();
            IP = new IPEndPoint(IPAddress.Any, 9999);
            server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            server.Bind(IP);

            Thread listen = new Thread(() => {
                try
                {
                    while (true)
                    {
                        server.Listen(100);
                        client = server.Accept();
                        clientList.Add(client);

                        byte[] laydodai = BitConverter.GetBytes(khoapublic.Length);
                        client.Send(laydodai);
                        byte[] Keypublic = khoapublic;
                        client.Send(Keypublic);
                        byte[] nhandodai = new byte[1024];
                        client.Receive(nhandodai);
                        nhankey = new byte[BitConverter.ToInt32(nhandodai, 0)];
                        client.Receive(nhankey);
                        keyclient = Convert.ToBase64String(nhankey);
                        textBox2.Text = keyclient;

                        diff.LayKhoaBiMat(nhankey);
                        khoabimat = diff.aes.Key;
                        keysecret = Convert.ToBase64String(khoabimat);
                        textBox4.Text = keysecret;
                        Thread receive = new Thread(Receive);
                        receive.IsBackground = true;
                        receive.Start(client);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                }
            });
            TaoKey();
            listen.IsBackground = true;
            listen.Start();
        }

        void TaoKey()
        {
            diff = new DiffieHellman();
            khoapublic = diff.PublicKey;
            keypublic = Convert.ToBase64String(khoapublic);
            textBox3.Text = keypublic;
        }

        void guilaipublickey()
        {
            byte[] batdauguikey = Encoding.UTF8.GetBytes("guikey");
            client.Send(batdauguikey);
            byte[] Keypublic = khoapublic;
            client.Send(Keypublic);
        }

        void guiLaiKeyChoClientVuaGui()
        {
            byte[] batdauguikey = Encoding.UTF8.GetBytes("guikeytoclient");
            client.Send(batdauguikey);
            byte[] Keypublic = khoapublic;
            client.Send(Keypublic);
        }
        int AddPadding()
        {
            string Timestamp = new DateTimeOffset(DateTime.UtcNow).ToUniversalTime().ToString("yyyyMMddHHmmssffff");
            string MHtimeStamp = md5.maHoaMd5(Timestamp);
            int soByteCuaChuoi = UTF8Encoding.UTF8.GetByteCount(textBox1.Text);
            int i = 0;
            string tmpTime = string.Empty;
            if (soByteCuaChuoi % 16 != 0)
            {
                i = 1;
                int length = soByteCuaChuoi;
                while (length % 16 != 0)
                {
                    tmpTime = MHtimeStamp.Substring(0, i);
                    length = length + 1;
                    i = i + 1;
                }

            }
            textBox1.Text = textBox1.Text + tmpTime;
            return i+2;
        }
        void Send(Socket client)
        {
            dateTimeIV = md5.maHoaMd5(DateTime.Now.ToString());
            string time = dateTimeIV.Substring(0, 16);
            dateTimeIv = Encoding.UTF8.GetBytes(time);
            string a = textBox4.Text.Substring(0, 32);
            byte[] key = Encoding.ASCII.GetBytes(a);
            int paddingValue = AddPadding();
            string _paddingValue = paddingValue.ToString();
            string s = aes.EncryptString(textBox1.Text +"|"+ _paddingValue, key, dateTimeIv);

            byte[] mahoa = diff.MaHoaDiffie(nhankey, s);
            byte[] dodai = BitConverter.GetBytes(mahoa.Length);
            byte[] initvector = diff.IV;
            if (client != null && textBox1.Text != string.Empty)
            {
                client.Send(dodai);
                client.Send(mahoa);
                client.Send(initvector);
            }
        }

        void AddMessage(string s)
        {
            textBox6.Text = "Client: " + s;
        }

        void Messagefromself(string s)
        {
            textBox6.Text = "Server: " + s;
        }

        void Receive(object obj)
        {
            Socket client = obj as Socket;
            try
            {
                while (true)
                {
                    data = new byte[1024*24];
                    client.Receive(data);
                    if (string.Equals(Encoding.UTF8.GetString(data), "guikeyserver", StringComparison.InvariantCultureIgnoreCase))
                    {
                        nhankeydadoi = new byte[140];
                        client.Receive(nhankeydadoi);
                        keypublic = Convert.ToBase64String(nhankeydadoi);
                        textBox2.Text = keypublic;
                        diff.LayKhoaBiMat(nhankeydadoi);
                        khoabimat = diff.aes.Key;
                        keysecret = Convert.ToBase64String(khoabimat);
                        textBox4.Text = keysecret;
                        nhankey = nhankeydadoi;
                    }
                    else if (string.Equals(Encoding.UTF8.GetString(data), "guikeytoserver", StringComparison.InvariantCultureIgnoreCase))
                    {
                        nhankeydadoi = new byte[140];
                        client.Receive(nhankeydadoi);
                        keypublic = Convert.ToBase64String(nhankeydadoi);
                        textBox2.Text = keypublic;
                        TaoKey();
                        diff.LayKhoaBiMat(nhankeydadoi);
                        khoabimat = diff.aes.Key;
                        keysecret = Convert.ToBase64String(khoabimat);
                        textBox4.Text = keysecret;
                        nhankey = nhankeydadoi;
                        guiLaiKeyChoClientVuaGui();
                    }
                    else
                    {
                        tinnhan = new byte[BitConverter.ToInt32(data, 0)];
                        client.Receive(tinnhan);
                        byte[] nhanvector = new byte[16];
                        client.Receive(nhanvector);
                        string message = diff.GiaiMaDiffie(nhankey, tinnhan, nhanvector);

                        dateTimeIV = md5.maHoaMd5(DateTime.Now.ToString());
                        string time = dateTimeIV.Substring(0, 16);
                        dateTimeIv = Encoding.UTF8.GetBytes(time);
                        string a = textBox4.Text.Substring(0, 32);
                        byte[] key = Encoding.ASCII.GetBytes(a);
                        string s = aes.DecryptString(message, key, dateTimeIv);

                        string[] arr = s.Split('|');
                        string padding = arr[1];
                        string result = s.Substring(0, s.Length - int.Parse(padding));
                        AddMessage(result);
                    }
                }
            }

            catch
            {
                clientList.Remove(client);
                client.Close();
            }

        }

        byte[] Serialize(object obj)
        {
            MemoryStream stream = new MemoryStream();
            BinaryFormatter formatter = new BinaryFormatter();

            formatter.Serialize(stream, obj);
            return stream.ToArray();
        }

        object Deserialize(byte[] data)
        {
            MemoryStream stream = new MemoryStream(data);
            BinaryFormatter formatter = new BinaryFormatter();
            return formatter.Deserialize(stream);
        }

        private void Server_FormClosed(object sender, FormClosedEventArgs e)
        {
            server.Close();
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            foreach (Socket item in clientList)
            {
                Send(item);
            }
            Messagefromself(textBox1.Text);
            textBox1.Clear();

        }

        private void Server_Load(object sender, EventArgs e)
        {

        }
    }
}
