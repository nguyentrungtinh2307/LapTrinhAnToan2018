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

namespace Client
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            CheckForIllegalCrossThreadCalls = false;

            Connect();
        }
        IPEndPoint IP;
        Socket client;
        AES aes = new AES();
        byte[] khoapublic;
        byte[] khoabimat;
        string keypublic;
        string keysecret;
        byte[] nhankey;
        byte[] nhankeydadoi;
        byte[] data;
        byte[] tinnhan;
        byte[] keypublicduocguilai = new byte[1024];
        DiffieHellman Diff = new DiffieHellman();
        string dateTimeIV;
        byte[] dateTimeIv;
        MD5 md5 = new MD5();

        void Connect()
        {
            IP = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 9999);
            client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                client.Connect(IP);
            }
            catch
            {
                MessageBox.Show("Không thể kết nối tới server", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                this.Close();
                return;
            }
            byte[] nhandodai = new byte[1024];
            client.Receive(nhandodai);

            nhankey = new byte[BitConverter.ToInt32(nhandodai, 0)];
            client.Receive(nhankey);

            keypublic = Convert.ToBase64String(nhankey);
            textBox2.Text = keypublic;
            TaoKey();
            Diff.LayKhoaBiMat(nhankey);
            khoabimat = Diff.aes.Key;
            keysecret = Convert.ToBase64String(khoabimat);
            textBox4.Text = keysecret;
            byte[] laydodai = BitConverter.GetBytes(khoapublic.Length);
            client.Send(laydodai);
            byte[] Keypublic = khoapublic;
            client.Send(Keypublic);
            Thread listen = new Thread(Receive);
            listen.IsBackground = true;
            listen.Start();
        }

        void TaoKey()
        {
            Diff = new DiffieHellman();
            khoapublic = Diff.PublicKey;
            keypublic = Convert.ToBase64String(khoapublic);
            textBox3.Text = keypublic;
        }

        void guilaipublickey()
        {
            byte[] batdauguikey = Encoding.UTF8.GetBytes("guikeyserver");
            client.Send(batdauguikey);
            byte[] Keypublic = khoapublic;
            client.Send(Keypublic);
        }

        void guiPublickeyChoServerKhiHetTime()
        {
            byte[] batdauguikey = Encoding.UTF8.GetBytes("guikeytoserver");
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
        void Send()
        {
            dateTimeIV = md5.maHoaMd5(DateTime.Now.ToString());
            string time = dateTimeIV.Substring(0, 16);
            dateTimeIv = Encoding.UTF8.GetBytes(time);
            string a = textBox4.Text.Substring(0, 32);
            byte[] key = Encoding.ASCII.GetBytes(a);

            int paddingValue = AddPadding();
            string _paddingValue = paddingValue.ToString();
            string s = aes.EncryptString(textBox1.Text + "|" + _paddingValue, key, dateTimeIv);


            byte[] mahoa = Diff.MaHoaDiffie(nhankey, s);
            byte[] dodai = BitConverter.GetBytes(mahoa.Length);
            byte[] initvector = Diff.IV;
            if (client != null && textBox1.Text != string.Empty)
            {
                client.Send(dodai);
                client.Send(mahoa);
                client.Send(initvector);
            }
        }

        void AddMessage(string s)
        {
            textBox6.Text = "Server: " + s;
            textBox1.Clear();
        }

        void AddSelfMessage(string s)
        {
        textBox6.Text = "Client: " + s;
            textBox1.Clear();
        }

        void Receive()
        {
            try
            {
                c: while (true)
                {
                    data = new byte[1024];
                    client.Receive(data);

                    if (string.Equals(Encoding.UTF8.GetString(data), "guikey", StringComparison.InvariantCultureIgnoreCase))
                    {
                        textBox2.Clear();
                        textBox4.Clear();
                        nhankeydadoi = new byte[140];
                        client.Receive(nhankeydadoi);
                        keypublic = Convert.ToBase64String(nhankeydadoi);
                        textBox2.Text = keypublic;
                        TaoKey();
                        Diff.LayKhoaBiMat(nhankeydadoi);
                        khoabimat = Diff.aes.Key;
                        keysecret = Convert.ToBase64String(khoabimat);
                        textBox4.Text = keysecret;
                        nhankey = nhankeydadoi;
                        guilaipublickey();
                    }
                    else if (string.Equals(Encoding.UTF8.GetString(data), "guikeytoclient", StringComparison.InvariantCultureIgnoreCase))
                    {
                        textBox2.Clear();
                        textBox4.Clear();
                        nhankeydadoi = new byte[140];
                        client.Receive(nhankeydadoi);
                        keypublic = Convert.ToBase64String(nhankeydadoi);
                        textBox2.Text = keypublic;
                        Diff.LayKhoaBiMat(nhankeydadoi);
                        khoabimat = Diff.aes.Key;
                        keysecret = Convert.ToBase64String(khoabimat);
                        textBox4.Text = keysecret;
                        nhankey = nhankeydadoi;
                    }
                    else
                    {
                        dateTimeIV = md5.maHoaMd5(DateTime.Now.ToString());
                        string time = dateTimeIV.Substring(0, 16);
                        dateTimeIv = Encoding.UTF8.GetBytes(time);

                        tinnhan = new byte[BitConverter.ToInt32(data, 0)];
                        client.Receive(tinnhan);
                        byte[] nhanvector = new byte[16];
                        client.Receive(nhanvector);
                        string message = Diff.GiaiMaDiffie(nhankey, tinnhan, nhanvector);
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

            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
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

        private void Client_FormClosed(object sender, FormClosedEventArgs e)
        {
            client.Close();
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            timer1.Stop();
            Send();
            AddSelfMessage(textBox1.Text);
            textBox1.Clear();
            sec = 21;
            timer1.Start();

        }

        AES AES = new AES();


        private void txtViewMessage_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        //thêm random
        private static string RandomString(string baseString, string character, int position)
        {
            var sb = new StringBuilder(baseString);

            sb.Insert(position, character);

            return sb.ToString();
        }

        int sec = 30;
        private void timer1_Tick(object sender, EventArgs e)
        {
            label1.Visible = true;
            label1.Text = sec.ToString();
            if (sec < 10)
            {
                label1.Text = "" + sec.ToString();
            }
            if (sec <= 0)
            {
                timer1.Stop();
                textBox2.Clear();
                textBox4.Clear();
                TaoKey();
                guiPublickeyChoServerKhiHetTime();
                laptime();
            }
            sec--;
        }


        private void Form1_Load(object sender, EventArgs e)
        {
            timer1.Start();
        }

        private void laptime()
        {
            sec = 31;
            timer1 = new System.Windows.Forms.Timer();
            timer1.Tick += new EventHandler(timer1_Tick);
            timer1.Interval = 1000;
            timer1.Start();
        }
    }
}
