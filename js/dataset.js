/**
 * Sentinel Web Showcase - Threat Dataset & Preset Index
 * Bundles reference intelligence to drive client-side interactive evaluations.
 */

const SENTINEL_DATASET = {
    // Known Datacenter, Hosting, and Commercial VPN ASNs
    HOSTING_ASNS: {
        16509: { name: "Amazon AWS", type: "Datacenter/Hosting", risk: 85 },
        14618: { name: "Amazon AWS", type: "Datacenter/Hosting", risk: 85 },
        15169: { name: "Google Cloud Platform", type: "Datacenter/Hosting", risk: 85 },
        8075:  { name: "Microsoft Azure", type: "Datacenter/Hosting", risk: 85 },
        14061: { name: "DigitalOcean", type: "Datacenter/Hosting", risk: 85 },
        24940: { name: "Hetzner Online GmbH", type: "Datacenter/Hosting", risk: 90 },
        16276: { name: "OVHcloud", type: "Datacenter/Hosting", risk: 90 },
        63949: { name: "Linode / Akamai Connected Cloud", type: "Datacenter/Hosting", risk: 85 },
        20473: { name: "Vultr / The Constant Company", type: "Datacenter/Hosting", risk: 85 },
        16265: { name: "Leaseweb", type: "Datacenter/Hosting", risk: 90 },
        28753: { name: "Leaseweb Germany", type: "Datacenter/Hosting", risk: 90 },
        12876: { name: "Scaleway / Online SAS", type: "Datacenter/Hosting", risk: 85 },
        31898: { name: "Oracle Cloud", type: "Datacenter/Hosting", risk: 85 },
        45102: { name: "Alibaba Cloud", type: "Datacenter/Hosting", risk: 85 },
        206016:{ name: "Mullvad VPN", type: "Commercial VPN", risk: 95 },
        9009:  { name: "NordVPN / M247", type: "Commercial VPN", risk: 95 },
        62371: { name: "ProtonVPN", type: "Commercial VPN", risk: 95 },
        44477: { name: "Residential Proxy Gateway Node", type: "Residential Proxy", risk: 95 },
        51395: { name: "Rotating Proxy Gateway", type: "Rotating Proxy", risk: 95 },
        208294:{ name: "Tor Exit Node Relay", type: "Tor Exit Node", risk: 100 },
        13335: { name: "Cloudflare WARP / Proxy", type: "Proxy/VPN", risk: 75 }
    },

    // Keywords in ISP or Organization string that flag hosting/proxy
    SUSPICIOUS_KEYWORDS: [
        "vpn", "proxy", "hosting", "cloud", "server", "datacenter", "dedicated",
        "vps", "mullvad", "nordvpn", "proton", "wireguard", "ovh", "hetzner",
        "digitalocean", "linode", "vultr", "leaseweb", "choopa", "akamai",
        "contabo", "rackspace", "softlayer", "packet", "scaleway"
    ],

    // Preset IPs for instant live evaluation against the Cloudflare Edge API
    PRESETS: [
        {
            label: "Mullvad VPN",
            ip: "185.213.154.20",
            category: "Commercial VPN",
            expectedRisk: 95,
            asn: "AS206016",
            provider: "Mullvad VPN",
            country: "SE"
        },
        {
            label: "Hetzner Cloud VPS",
            ip: "78.46.12.34",
            category: "Datacenter VPS",
            expectedRisk: 90,
            asn: "AS24940",
            provider: "Hetzner Online GmbH",
            country: "DE"
        },
        {
            label: "Tor Exit Relay",
            ip: "185.220.101.5",
            category: "Tor Exit Node",
            expectedRisk: 100,
            asn: "AS208294",
            provider: "Tor Anonymous Network",
            country: "DE"
        },
        {
            label: "OVHcloud Dedicated",
            ip: "51.68.10.20",
            category: "Datacenter VPS",
            expectedRisk: 90,
            asn: "AS16276",
            provider: "OVHcloud SAS",
            country: "FR"
        },
        {
            label: "NordVPN Endpoint",
            ip: "185.120.248.15",
            category: "Commercial VPN",
            expectedRisk: 95,
            asn: "AS9009",
            provider: "NordVPN",
            country: "PA"
        },
        {
            label: "DigitalOcean Droplet",
            ip: "104.131.2.3",
            category: "Cloud VPS",
            expectedRisk: 85,
            asn: "AS14061",
            provider: "DigitalOcean, LLC",
            country: "US"
        },
        {
            label: "Residential Broadband",
            ip: "24.130.12.8",
            category: "Residential ISP",
            expectedRisk: 0,
            asn: "AS7922",
            provider: "Comcast Cable Communications",
            country: "US"
        }
    ]
};
