using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpPcap;
using System.Text.RegularExpressions;

namespace PacketCapture
{
    class Program
    {
        private static NLog.Logger file_logger = NLog.LogManager.GetLogger("LOGFILE");
        private static NLog.Logger sniffer_logger = NLog.LogManager.GetLogger("SNIFFER");


        /// <summary>
        /// インターフェイスの一覧を取得したデータを保存する
        /// </summary>
        private struct deviceInterface
        {
            public SharpPcap.Npcap.NpcapDevice device;
            public string description;
        }


        static void Main(string[] args)
        {
            string ver = SharpPcap.Version.VersionString;
            /* Print SharpPcap version */
            Console.WriteLine($"SharpPcap {ver}, Websocket PacketCapture");
            Console.WriteLine();


            // キャプチャするデバイスを選択する
            deviceInterface targetDevice = getTargetDevice();
            if (targetDevice.device == null)
            {
                return;
            }

            SharpPcap.Npcap.NpcapDevice device = targetDevice.device;
            string deviceDescription = targetDevice.description;


            // キャプチャする間隔を指定する
            int interval = getNetworkInterfaceMonitoringIntervalTime();


            //Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = interval;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);



            // パケットキャプチャー自体にパケットが取り込まれないようにフィルターをかける
            // フィルターの指定形式はBPF(Wiresharkとかでインターフェイスに直接かける時の形式で指定)

            // filter source ip
            string srcIp = getSourceIp();

            // filter source port
            string srcPort = getSourcePort();


            string filter = "";


            if (srcIp != "" && srcPort == "")
            {
                filter = $"ip src host {srcIp}";
            }
            else if (srcIp == "" && srcPort != "")
            {
                filter = $"tcp src port {srcPort}";
            }
            else if (srcIp != "" && srcPort != "")
            {
                filter = $"ip src host {srcIp} and tcp src port {srcPort}";
            }


            device.Filter = filter;

            Console.WriteLine();
            Console.WriteLine
                ($"-- The following tcpdump filter will be applied: \"{filter}\"");
            Console.WriteLine();
            Console.WriteLine("Capture start");
            Console.WriteLine
                ($"-- Listening on \"{deviceDescription}\", hit 'Ctrl-C' to exit...");

            // Start capture 'INFINTE' number of packets
            device.Capture();
            Console.ReadLine();
            device.StopCapture();

            // Close the pcap device
            // (Note: this line will never be called since
            //  we're capturing infinite number of packets
            device.Close();
        }


        /// <summary>
        /// IPアドレスの形式かどうかチェックして一致すればtrue
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        static private bool checkIpString(string str)
        {

            if (string.IsNullOrEmpty(str))
            {
                throw new ArgumentException("str is null or empty.");
            }

            if (str.Length < 7 || str.Length > 15)
            {
                // throw new FormatException("str is illegal fortmat (" + str + ")");
                return false;
            }

            Match m = Regex.Match(str, @"^(\d+)\.(\d+)\.(\d+)\.(\d+)$");
            if (m.Success)
            {
                for (int i = 1; i < 5; i++)
                {
                    if (!isInByteRange(m.Groups[i].Value))
                    {
                        // throw new FormatException("str is illegal fortmat (" + str + ")");
                        return false;
                    }
                }
            }
            return true;
        }

        // 0 ～ 255 の範囲内かどうかチェックする
        static private bool isInByteRange(string block)
        {
            byte result;
            return byte.TryParse(block, out result);
        }



        /// <summary>
        /// パケットをキャプチャーするためのソースIPを入力して返す
        /// フィルターしない場合は空の文字列を返す
        /// </summary>
        /// <returns></returns>
        static private string getSourceIp()
        {
            while (true)
            {
                Console.WriteLine();
                Console.Write("Capture target input source ip: ");

                string ip = Console.ReadLine();

                if (ip == "")
                {
                    return "";
                }

                if (checkIpString(ip))
                {
                    return ip;
                }

                Console.WriteLine("");
                Console.WriteLine("Invalid ip address");
            }

        }


        static private bool checkPortString(string portString)
        {
            int port;

            bool success = int.TryParse(portString, out port);

            return success;
        }

        static private string getSourcePort()
        {
            while (true)
            {
                Console.Write("Capture target input source port: ");

                string port = Console.ReadLine();

                if (port == "")
                {
                    return "";
                }

                if (checkPortString(port))
                {
                    return port;
                }

                Console.WriteLine("");
                Console.WriteLine("Invalid port number");
            }
        }



        /// <summary>
        /// インターフェイスからパケットをキャプチャする間隔を入力する
        /// その際に入力値が適正かどうかチェックする
        /// </summary>
        /// <returns></returns>
        private static int getTargetServerIpAddress()
        {
            int ms = 0;
            string i;

            while (true)
            {
                Console.Write("Enter the interval to monitor the network interface(ms): ");
                i = Console.ReadLine();

                if (int.TryParse(i, out ms))
                {
                    return ms;
                }
                else
                {
                    Console.WriteLine("Please enter a number");
                    Console.WriteLine();
                }

            }
        }



        /// <summary>
        /// ネットワークインターフェースを監視する間隔を設定する(ms)
        /// </summary>
        /// <returns></returns>
        private static int getNetworkInterfaceMonitoringIntervalTime()
        {
            int ms = 0;

            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("Enter the interval to monitor the network interface. Default: 10(ms)");
                Console.Write("Inpute time(ms): ");
                string inputMs = Console.ReadLine();

                if (inputMs == "")
                {
                    return 10;
                }

                if (int.TryParse(inputMs, out ms))
                {
                    if (ms > 0)
                    {
                        return ms;
                    }
                }

                Console.WriteLine();
                Console.WriteLine("Invalid input interval(ms)");
            }
        }



        /// <summary>
        /// キャプチャするネットワークインターフェースを選択する際のインターフェイスの名称とIPアドレスを取得して返す
        /// </summary>
        /// <param name="device"></param>
        /// <returns></returns>
        private static (string, string) DeviceInterfaceIpV4Address(SharpPcap.Npcap.NpcapDevice device)
        {
            var interfaces = (SharpPcap.LibPcap.PcapInterface)device.Interface;

            foreach (var iface in interfaces.Addresses)
            {
                if (iface.Addr.ipAddress == null)
                {
                    continue;
                }

                if (iface.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    string ifAddress = iface.Addr.ipAddress.ToString();
                    string ifName = interfaces.FriendlyName;

                    return (ifName, ifAddress);
                }
            }

            return ("", "");
        }



        /// <summary>
        /// ネットワークインターフェースの一覧を取得し、その中からキャプチャに利用するインターフェイスを選択して返す
        /// </summary>
        /// <returns></returns>
        private static deviceInterface getTargetDevice()
        {
            /* Retrieve the device list */
            var devices = CaptureDeviceList.Instance;

            /*			List<SharpPcap.Npcap.NpcapDevice> targetDevices = new List<SharpPcap.Npcap.NpcapDevice>();
			*/

            List<deviceInterface> targetDevices = new List<deviceInterface>();


            /*If no device exists, print error */
            if (devices.Count < 1)
            {
                Console.WriteLine("No device found on this machine");
                return new deviceInterface();
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine();
            Console.WriteLine("No   Interface Name                           IP Address");
            Console.WriteLine("------------------------------------------------------------");

            int i = 1;

            /* Scan the list printing every entry */
            foreach (var dev in devices)
            {
                if (((SharpPcap.LibPcap.LibPcapLiveDevice)dev).Addresses.Count == 0)
                {
                    continue;
                }

                var (ifName, ipAddress) = DeviceInterfaceIpV4Address((SharpPcap.Npcap.NpcapDevice)dev);

                if (ifName == "")
                {
                    continue;
                }


                /* Description */
                Console.WriteLine($"{i,2}). {ifName,-40} {ipAddress}");

                var target = new deviceInterface();
                target.device = (SharpPcap.Npcap.NpcapDevice)dev;
                target.description = ifName;

                targetDevices.Add(target);
                i++;
            }


            // インターフェイスの一覧からターゲットとするインターフェイスを選択する
            while (true)
            {
                Console.WriteLine();
                Console.Write("Please choose a device no to capture: ");
                string inputTargetNo = Console.ReadLine();

                int targetNo;
                if (int.TryParse(inputTargetNo, out targetNo))
                {
                    if (targetDevices.Count >= targetNo && targetNo > 0)
                    {
                        var device = targetDevices[targetNo - 1];
                        return device;
                    }
                }

                Console.WriteLine("Invalid choose target no.");
                Console.WriteLine();
            }

        }



        /// <summary>
        /// インターフェイスから取得したパケットを受信した際に呼び出されるコールバック
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
            if (tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;

                string p = $"{time.Hour:D2}:{time.Minute:D2}:{time.Second:D2},{time.Millisecond:D3} Len={len,4} {srcIp,13}:{srcPort,-5} -> {dstIp,13}:{dstPort,-5}";

                file_logger.Info(p);


                string payload = BitConverter.ToString(tcpPacket.Bytes).Replace("-", "");
                string pp = $"{time.Hour:D2}:{time.Minute:D2}:{time.Second:D2},{time.Millisecond:D3} Seq={tcpPacket.SequenceNumber,10} Len={len,4} {payload}";

                sniffer_logger.Info(pp);

                //Console.WriteLine(p);
            }
        }
    }
}
