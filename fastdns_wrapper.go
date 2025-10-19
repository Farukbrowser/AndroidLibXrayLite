package libv2ray

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// FastDNSManager manages DNS resolvers and provides high-performance DNS resolution
// Note: On Android, XDP sockets are not available, so we use optimized standard DNS
type FastDNSManager struct {
	resolvers map[string]*dns.Client
	servers   map[string]string
	mutex     sync.RWMutex
	enabled   bool
}

// NewFastDNSManager creates a new FastDNS manager
func NewFastDNSManager() *FastDNSManager {
	return &FastDNSManager{
		resolvers: make(map[string]*dns.Client),
		servers:   make(map[string]string),
		enabled:   true,
	}
}

// AddResolver adds a new DNS resolver
func (f *FastDNSManager) AddResolver(name string, resolverIP string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// Create optimized DNS client
	client := new(dns.Client)
	client.Timeout = 3 * time.Second
	client.ReadTimeout = 2 * time.Second
	client.WriteTimeout = 2 * time.Second
	
	// Use UDP for better performance on mobile
	client.Net = "udp"

	f.resolvers[name] = client
	f.servers[name] = resolverIP + ":53"
	return nil
}

// QueryDNS performs a DNS query using optimized DNS client
func (f *FastDNSManager) QueryDNS(resolverName string, domain string, qtype uint16) (*dns.Msg, error) {
	f.mutex.RLock()
	client, clientExists := f.resolvers[resolverName]
	server, serverExists := f.servers[resolverName]
	f.mutex.RUnlock()

	if !clientExists || !serverExists || !f.enabled {
		// Fallback to standard DNS
		return f.fallbackQuery(domain, qtype)
	}

	// Create DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	// Query using optimized DNS client
	response, _, err := client.Exchange(msg, server)
	if err != nil {
		// Fallback to standard DNS on error
		return f.fallbackQuery(domain, qtype)
	}

	return response, nil
}

// fallbackQuery performs standard DNS query as fallback
func (f *FastDNSManager) fallbackQuery(domain string, qtype uint16) (*dns.Msg, error) {
	client := new(dns.Client)
	client.Timeout = 5 * time.Second
	client.Net = "udp"

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	// Try multiple public DNS servers
	servers := []string{"8.8.8.8:53", "1.1.1.1:53", "208.67.222.222:53"}
	
	for _, server := range servers {
		response, _, err := client.Exchange(msg, server)
		if err == nil && response != nil && response.Rcode == dns.RcodeSuccess {
			return response, nil
		}
	}

	return nil, fmt.Errorf("all DNS servers failed for domain: %s", domain)
}

// ResolveDomain resolves a domain to IP addresses
func (f *FastDNSManager) ResolveDomain(resolverName string, domain string) ([]net.IP, error) {
	// Try A record first
	response, err := f.QueryDNS(resolverName, domain, dns.TypeA)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, answer := range response.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}

	// If no A records, try AAAA records (IPv6)
	if len(ips) == 0 {
		response, err = f.QueryDNS(resolverName, domain, dns.TypeAAAA)
		if err != nil {
			return nil, err
		}

		for _, answer := range response.Answer {
			if aaaa, ok := answer.(*dns.AAAA); ok {
				ips = append(ips, aaaa.AAAA)
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for domain: %s", domain)
	}

	return ips, nil
}

// MeasureDNSLatency measures the latency of DNS resolution
func (f *FastDNSManager) MeasureDNSLatency(resolverName string, domain string) (time.Duration, error) {
	start := time.Now()
	_, err := f.QueryDNS(resolverName, domain, dns.TypeA)
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// Close closes all DNS clients
func (f *FastDNSManager) Close() {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// Clear all resolvers
	f.resolvers = make(map[string]*dns.Client)
	f.servers = make(map[string]string)
	f.enabled = false
}

// IsEnabled returns whether FastDNS is enabled
func (f *FastDNSManager) IsEnabled() bool {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.enabled
}

// GetResolverCount returns the number of active resolvers
func (f *FastDNSManager) GetResolverCount() int {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return len(f.resolvers)
}

// Global FastDNS manager instance
var globalFastDNSManager *FastDNSManager
var globalFastDNSOnce sync.Once

// InitGlobalFastDNS initializes the global FastDNS manager
func InitGlobalFastDNS() error {
	var err error
	globalFastDNSOnce.Do(func() {
		globalFastDNSManager = NewFastDNSManager()
		
		// Add default resolvers optimized for mobile/Android
		resolvers := map[string]string{
			"cloudflare": "1.1.1.1",
			"google":     "8.8.8.8",
			"quad9":      "9.9.9.9",
		}

		// Add resolvers with error handling
		for name, ip := range resolvers {
			if addErr := globalFastDNSManager.AddResolver(name, ip); addErr != nil {
				err = fmt.Errorf("failed to add resolver %s: %v", name, addErr)
				return
			}
		}
	})
	return err
}

// GetFastDNSManager returns the global FastDNS manager
func GetFastDNSManager() *FastDNSManager {
	return globalFastDNSManager
}