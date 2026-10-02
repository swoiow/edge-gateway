use std::net::IpAddr;

pub(crate) fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => {
            address.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(address))
        }
        address => address,
    }
}

#[derive(Clone)]
pub(crate) enum IpNetwork {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl IpNetwork {
    pub(crate) fn parse(value: &str) -> Result<Self, &'static str> {
        let (address, prefix) = value.split_once('/').ok_or("CIDR prefix is required")?;
        let address = address.parse::<IpAddr>().map_err(|_| "invalid CIDR IP")?;
        let prefix = prefix.parse::<u32>().map_err(|_| "invalid CIDR prefix")?;
        match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                let network = u32::from(address);
                if network & mask != network {
                    return Err("CIDR must use the canonical network address");
                }
                Ok(Self::V4 { network, mask })
            }
            IpAddr::V6(address) if prefix <= 128 && address.to_ipv4_mapped().is_none() => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                let network = u128::from(address);
                if network & mask != network {
                    return Err("CIDR must use the canonical network address");
                }
                Ok(Self::V6 { network, mask })
            }
            _ => Err("invalid CIDR prefix or IPv4-mapped IPv6 CIDR; use IPv4 CIDR instead"),
        }
    }

    pub(crate) fn contains(&self, address: IpAddr) -> bool {
        match (self, normalize_ip(address)) {
            (Self::V4 { network, mask }, IpAddr::V4(address)) => {
                u32::from(address) & mask == *network
            }
            (Self::V6 { network, mask }, IpAddr::V6(address)) => {
                u128::from(address) & mask == *network
            }
            _ => false,
        }
    }
}
