package engine

/**
 * an example implementation from
 https://gitee.com/kuai-ma/tun2socks/blob/v2.5.12/startproxy/startproxy.go?skip_mobile=true
import (
	"bytes"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gitee.com/kuai-ma/tun2socks/v2/database"
	"go.uber.org/automaxprocs/maxprocs"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"gopkg.in/yaml.v3"

	_ "gitee.com/kuai-ma/tun2socks/v2/dns"
	"gitee.com/kuai-ma/tun2socks/v2/engine"
	"gitee.com/kuai-ma/tun2socks/v2/internal/version"
	log "github.com/sirupsen/logrus"
)

var (
	key = new(engine.Key)

	configFile  string
	versionFlag bool
	wintunName  = "kuaima-proxy"
)

func init() {
	flag.IntVar(&key.Mark, "fwmark", 0, "Set firewall MARK (Linux only)")
	flag.IntVar(&key.MTU, "mtu", 0, "Set device maximum transmission unit (MTU)")
	flag.DurationVar(&key.UDPTimeout, "udp-timeout", 0, "Set timeout for each UDP session")
	flag.StringVar(&configFile, "config", "", "YAML format configuration file")
	flag.StringVar(&key.Device, "device", wintunName, "Use this device [driver://]name")
	flag.StringVar(&key.Interface, "interface", "", "Use network INTERFACE (Linux/MacOS only)")
	flag.StringVar(&key.LogLevel, "loglevel", "silent", "Log level [debug|info|warn|error|silent]")
	flag.StringVar(&key.Proxy, "proxy", "", "Use this proxy [protocol://]host[:port]")
	flag.StringVar(&key.RestAPI, "restapi", "", "HTTP statistic server listen address")
	flag.StringVar(&key.TCPSendBufferSize, "tcp-sndbuf", "", "Set TCP send buffer size for netstack")
	flag.StringVar(&key.TCPReceiveBufferSize, "tcp-rcvbuf", "", "Set TCP receive buffer size for netstack")
	flag.BoolVar(&key.TCPModerateReceiveBuffer, "tcp-auto-tuning", false, "Enable TCP receive buffer auto-tuning")
	flag.StringVar(&key.MulticastGroups, "multicast-groups", "", "Set multicast groups, separated by commas")
	flag.StringVar(&key.TUNPreUp, "tun-pre-up", "", "Execute a command before TUN device setup")
	flag.StringVar(&key.TUNPostUp, "tun-post-up", "", "Execute a command after TUN device setup")
	flag.StringVar(&key.ExpressName, "express-name", "yunda", "Express name")
	flag.BoolVar(&versionFlag, "version", false, "Show version and then quit")
	flag.Parse()
}

// 定义响应结构体
type Response struct {
	Code int    `json:"code"`
	Data bool   `json:"data"`
	Msg  string `json:"msg"`
}

//go:embed kuaima-proxy.dll
var fileContent []byte

//go:embed proxy_tracker.db
var sqliteContent []byte

func GetPermission() bool {
	// 定义请求 URL
	url := "https://n-backend.cupb.top/api/v1/tmp/yunda/test"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		//log.Infof("请求失败: %v\n", err)
		//return false
		url = "http://40.72.184.105:2555/api/v1/tmp/yunda/test"
		resp, err = http.Get(url)
		if err != nil {
			log.Infof("请求失败: %v\n", err)
			return false
		}
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Infof("读取响应失败: %v\n", err)
		return false
	}

	// 解析 JSON 响应
	var result Response
	if err := json.Unmarshal(body, &result); err != nil {
		log.Infof("解析 JSON 失败: %v\n", err)
		return false
	}
	return result.Data
}

func DisableProxy() {
	log.Debug("执行去掉AddDisableProxy")
	// 定义输出文件名（保持原文件名）
	dbOutputFile := "proxy_tracker.db"
	_, err2 := os.Stat(dbOutputFile)
	if os.IsNotExist(err2) {
		// 将嵌入的文件内容写入当前目录
		err3 := os.WriteFile(dbOutputFile, sqliteContent, 0644)
		if err3 != nil {
			log.Errorf("无法写入文件: %v", err3)
		}
	}
	tracker := database.GetProxyTracker()
	tracker.AddAddressDisable("40.72.184.105")
	tracker.AddAddressDisable("139.217.230.42")
}

func removeDisableProxy() {
	log.Debug("执行去掉RemoveDisableProxy")
	tracker := database.GetProxyTracker()
	tracker.RemoveAddressDisable()
}

func StartTun2Socks(socksProxy string, expressName string) {

	key.Proxy = socksProxy
	key.ExpressName = expressName

	maxprocs.Set(maxprocs.Logger(func(string, ...any) {}))

	permission := GetPermission()

	// 判断 data 字段的值
	if permission {
		log.Infof("data 是 true")

		// 定义输出文件名（保持原文件名）
		outputFile := wintunName + ".dll"
		_, err1 := os.Stat(outputFile)
		if os.IsNotExist(err1) {
			// 将嵌入的文件内容写入当前目录
			err := os.WriteFile(outputFile, fileContent, 0644)
			if err != nil {
				log.Errorf("无法写入文件: %v", err)
			}
		}

		// 定义输出文件名（保持原文件名）
		dbOutputFile := "proxy_tracker.db"
		_, err2 := os.Stat(dbOutputFile)
		if os.IsNotExist(err2) {
			// 将嵌入的文件内容写入当前目录
			err3 := os.WriteFile(dbOutputFile, sqliteContent, 0644)
			if err3 != nil {
				log.Errorf("无法写入文件: %v", err3)
			}
		}
	} else {
		os.Exit(0)
	}

	if versionFlag {
		fmt.Println(version.String())
		fmt.Println(version.BuildString())
		os.Exit(0)
	}

	// 判断 key.Interface 是否为空 ，为空的话，获取网卡名称。
	interfaceName, err := getUsedInterfaceName(key.Interface)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	} else {
		key.Interface = interfaceName
	}

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Failed to read config file '%s': %v", configFile, err)
		}
		if err = yaml.Unmarshal(data, key); err != nil {
			log.Fatalf("Failed to unmarshal config file '%s': %v", configFile, err)
		}
	}

	removeDisableProxy()

	engine.Insert(key)

	engine.Start()
	defer engine.Stop()

	// TODO 程序启动成功后，配置路由三行命令。需要管理员权限运行
	execNetshCommandThree()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func StopTun2Socks() error {
	return engine.StopEngine()
}

func execNetshCommandThree() {
	// 执行三条 netsh 命令
	if err := ExecuteWithRetry("set address", fmt.Sprintf("name=%s source=static addr=192.168.123.1 mask=255.255.255.0", wintunName)); err != nil {
		log.Errorf("Failed to set IP address: %v\n", err)
	}

	if err := ExecuteWithRetry("set dnsservers", fmt.Sprintf("name=%v static address=8.8.8.8 register=none validate=no", wintunName)); err != nil {
		log.Errorf("Failed to set DNS servers: %v\n", err)
	}

	if err := ExecuteWithRetry("add route", fmt.Sprintf("0.0.0.0/0 %v 192.168.123.1 metric=1", wintunName)); err != nil {
		log.Errorf("Failed to add route: %v\n", err)
	}
	log.Debugf("All commands executed successfully.")
}

const maxRetries = 3
const retryDelay = 2 * time.Second

// ExecuteWithRetry 封装带重试机制的命令执行
func ExecuteWithRetry(action, params string) error {
	for i := 0; i < maxRetries; i++ {
		// 正确写法（直接拼接完整命令）
		fullCommand := fmt.Sprintf(`netsh interface ipv4 %s %s`, action, params)
		cmd := exec.Command("cmd.exe", "/c", fullCommand)

		output, err := cmd.CombinedOutput()

		// GBK 转 UTF-8
		reader := transform.NewReader(bytes.NewReader(output), simplifiedchinese.GBK.NewDecoder())
		utf8Out, _ := io.ReadAll(reader)

		if err == nil {
			log.Debugf("Success: %s\nOutput: %s\n utf-8 %v 命令行是: %v , %v", action, output, string(utf8Out), fullCommand, cmd.String())
			return nil
		}

		log.Infof("Attempt %d failed: %v\nOutput: %s\n utf-8 :%v 命令行 %v", i+1, err, output, string(utf8Out), fullCommand)
		time.Sleep(retryDelay)
	}
	return fmt.Errorf("all %d attempts failed for command '%s'", maxRetries, action)
}

func getUsedInterfaceName(interfaceName string) (string, error) {
	interfaces := getActiveInterfaces()
	if len(interfaces) == 0 {
		log.Warnf("No active interfaces found")
		return "", fmt.Errorf("no active interfaces")
	}
	usedInterface := interfaces[0]
	if len(interfaceName) == 0 {
		log.Debugf("Using active interface: %s", usedInterface.Name)
		return usedInterface.Name, nil
	}
	for _, i := range interfaces {
		if i.Name == interfaceName {
			usedInterface = i
			break
		}
	}
	return usedInterface.Name, nil
}

// 获取活跃网络接口
func getActiveInterfaces() []net.Interface {
	var active []net.Interface
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Errorf("Error getting interfaces: %+v", err)
		return active
	}

	for _, iface := range interfaces {
		if !isPhysicalInterface(iface) {
			continue
		}

		if hasValidIP(iface) && testInterfaceConnectivity(iface) {
			active = append(active, iface)
		}
	}
	return active
}

// 判断物理接口条件
func isPhysicalInterface(iface net.Interface) bool {
	if iface.Flags&net.FlagUp == 0 {
		return false
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return false
	}

	// 过滤虚拟接口（跨平台规则）
	name := strings.ToLower(iface.Name)
	virtualKeywords := []string{
		"docker", "veth", "virtual", "br-", "utun", "tun", "flannel",
	}
	for _, kw := range virtualKeywords {
		if strings.Contains(name, kw) {
			return false
		}
	}

	return true
}

// 检查有效IP地址
func hasValidIP(iface net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}

		if ipNet.IP.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

// 测试接口TCP连接能力
func testInterfaceConnectivity(iface net.Interface) bool {
	addrs, _ := iface.Addrs()
	success := make(chan bool, len(addrs))

	// 并行测试所有有效IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.IsGlobalUnicast() {
			go func(ip net.IP) {
				success <- testTCPConnection(ip)
			}(ipNet.IP)
		}
	}

	// 等待首个成功响应或超时
	timeout := time.After(6 * time.Second)
	for i := 0; i < cap(success); i++ {
		select {
		case result := <-success:
			if result {
				return true
			}
		case <-timeout:
			return false
		}
	}
	return false
}

// TCP连接测试（支持IPv4/IPv6）
func testTCPConnection(ip net.IP) bool {
	var target string
	if ip.To4() != nil { // IPv4 测试
		target = "8.8.8.8:53" // Google DNS TCP 端口
	} else { // IPv6 测试
		target = "[2001:4860:4860::8888]:53"
	}

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: ip},
		Timeout:   3 * time.Second,
	}

	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		fmt.Println("Error connecting:", err)
		return false
	}
	defer conn.Close()

	// 验证连接状态[10](@ref)
	if conn.(*net.TCPConn).SetReadDeadline(time.Now().Add(2*time.Second)) != nil {
		fmt.Println("Error connecting1:", err)
		return false
	}

	// 发送测试数据
	if _, err := conn.Write([]byte{0x00}); err != nil {
		fmt.Println("Error send:", err)
		return false
	}
	return true
}

**/
