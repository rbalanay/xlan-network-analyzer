//
//  ContentView.swift
//  Network Analyzer
//
//  Created by Ron Balanay on 11/12/20.
//

import SwiftUI
import Ipify
import Network
import SystemConfiguration.CaptiveNetwork

struct ContentView: View {
    @ObservedObject var gatewayFinder: GatewayFinder = GatewayFinder()
    @ObservedObject var ipFinder: IpFinder = IpFinder()

    @State var value = 0
    @State private var key = ""
    var body: some View {
        VStack {
            //Title
            Text("xLAN Network Analyzer")
                .font(.title)
            //Aligns external / local IP / SSID horiontally
            HStack {
                Spacer()
                //External IP address
                VStack {
                    if(isDarkMode()) {
                        Image("external_white")
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 60, height: 60.0)
                    } else {
                        Image("external_black")
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 60, height: 60.0)
                    }
                    Text("External IP")
                    //Retrieve external IP address and output as text
                    let extaddr = ipFinder.getExternalAddress(key)
                    Text(ipFinder.ipAddress)
                }
                Spacer()
                //Local IP address
                VStack {
                    if(isDarkMode()) {
                        Image("local_white")
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 60, height: 60.0)
                    } else {
                        Image("local_black")
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 60, height: 60.0)
                    }
                    Text("Local IP")
                    //Retrieve local IP address and output as text
                    if let addr = getWiFiAddress() {
                        Text(addr)
                    } else {
                        Text("N/A")
                    }
                     }
                Spacer()
                //SSID
                VStack {
                    if(isDarkMode()) {
                        Image("ssid_white")
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 60, height: 60.0)
                    } else {
                        Image("ssid_black")
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 60, height: 60.0)
                    }
                    Text("Interface Name")
                    //Retrieve SSID and output as text
                    let ssid = fetchSSIDInfo()
                    Text(ssid)
                }
            }
        }
        
        //Gateway / Subnet mask / Preferred DNS / Secondary DNS information
        List(){
            Section(header: Text("Gateway")) {
                var testgate = "test"
                //Retrieve gateway and output as text
                let gateway = gatewayFinder.getGatewayInfo { (remoteHost) in
                    testgate = remoteHost
                    print(testgate)
                }
                Text(gatewayFinder.remoteHost)
            }
            Section(header: Text("Subnet mask")) {
                //Retrieve subnet mask and output as text
                let netmask = getIFAddresses().last!.netmask
                Text(netmask)
            }
            Section(header: Text("Preferred DNS")) {
                let servers = Resolver().getservers().map(Resolver.getnameinfo)
                Text(servers[0])
            }
            Section(header: Text("Secondary DNS")) {
                if(servers[1]) {
                    Text(servers[1])
                } else {
                    Text("N/A")
                }
            }
        }
    }
}
func fetchSSIDInfo() ->  String? {
   if let interfaces = CNCopySupportedInterfaces() {
       for i in 0..<CFArrayGetCount(interfaces){
           let interfaceName: UnsafeRawPointer = CFArrayGetValueAtIndex(interfaces, i)
           let rec = unsafeBitCast(interfaceName, to: AnyObject.self)
           let unsafeInterfaceData = CNCopyCurrentNetworkInfo("\(rec)" as CFString)
          
           if let unsafeInterfaceData = unsafeInterfaceData as? Dictionary<AnyHashable, Any> {
               return unsafeInterfaceData["SSID"] as? String
           }
       }
   }
   return nil
}
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

//get gateway
class GatewayFinder: ObservableObject {
    @Published var remoteHost: String = ""
    func getGatewayInfo(completionHandler: @escaping (String) -> ()) {
        let monitor = NWPathMonitor(requiredInterfaceType: .wifi)
        monitor.pathUpdateHandler = { path in
            if let endpoint = path.gateways.first {
                switch endpoint {
                case .hostPort(let host, _):
                    self.remoteHost = host.debugDescription
                    print("Gateway: \(self.remoteHost)")
                    // Use callback here to return the ip address to the caller
                    completionHandler(self.remoteHost)
                default:
                    break
                }
            } else {
                print("Wifi connection may be dropped.")
            }
        }
        monitor.start(queue: DispatchQueue(label: "nwpathmonitor.queue"))
    }
}

//get local IP address
class IpFinder: ObservableObject {
    @Published var ipAddress: String = ""
    
    func getExternalAddress(_ key: String) {
        var test = key
        Ipify.getPublicIPAddress { [self] result in
            switch result {
            case .success(let ip):
                ipAddress = ip
            case .failure(let error):
                print(error.errorDescription)
            }
        }
    }
    
}
	
// Return IP address of WiFi interface (en0) as a String, or `nil`
func getWiFiAddress() -> String? {
    var address : String?

    // Get list of all interfaces on the local machine:
    var ifaddr : UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0 else { return nil }
    guard let firstAddr = ifaddr else { return nil }

    // For each interface ...
    for ifptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
        let interface = ifptr.pointee

        // Check for IPv4 or IPv6 interface:
        let addrFamily = interface.ifa_addr.pointee.sa_family
        if addrFamily == UInt8(AF_INET) || addrFamily == UInt8(AF_INET6) {

            // Check interface name:
            let name = String(cString: interface.ifa_name)
            if  name == "en0" {

                // Convert interface address to a human readable string:
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                getnameinfo(interface.ifa_addr, socklen_t(interface.ifa_addr.pointee.sa_len),
                            &hostname, socklen_t(hostname.count),
                            nil, socklen_t(0), NI_NUMERICHOST)
                address = String(cString: hostname)
            }
        }
    }
    freeifaddrs(ifaddr)

    return address
}

struct NetInfo {
      let ip: String
      let netmask: String
  }
  
  // Get the local ip addresses used by this node
func getIFAddresses() -> [NetInfo] {
      var addresses = [NetInfo]()
      
      // Get list of all interfaces on the local machine:
      var ifaddr : UnsafeMutablePointer<ifaddrs>? = nil
      if getifaddrs(&ifaddr) == 0 {
          
              var ptr = ifaddr;
              while ptr != nil {
              
              let flags = Int32((ptr?.pointee.ifa_flags)!)
              var addr = ptr?.pointee.ifa_addr.pointee
              
              // Check for running IPv4, IPv6 interfaces. Skip the loopback interface.
              if (flags & (IFF_UP|IFF_RUNNING|IFF_LOOPBACK)) == (IFF_UP|IFF_RUNNING) {
                  if addr?.sa_family == UInt8(AF_INET) || addr?.sa_family == UInt8(AF_INET6) {
                      
                      // Convert interface address to a human readable string:
                      var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                      if (getnameinfo(&addr!, socklen_t((addr?.sa_len)!), &hostname, socklen_t(hostname.count),
                                      nil, socklen_t(0), NI_NUMERICHOST) == 0) {
                          if let address = String.init(validatingUTF8:hostname) {
                              
                              var net = ptr?.pointee.ifa_netmask.pointee
                              var netmaskName = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                              getnameinfo(&net!, socklen_t((net?.sa_len)!), &netmaskName, socklen_t(netmaskName.count),
                                          nil, socklen_t(0), NI_NUMERICHOST)// == 0
                              if let netmask = String.init(validatingUTF8:netmaskName) {
                                  addresses.append(NetInfo(ip: address, netmask: netmask))
                              }
                          }
                      }
                  }
              }
              ptr = ptr?.pointee.ifa_next
              }
          freeifaddrs(ifaddr)
      }
      return addresses
  }

func isDarkMode() -> Bool{
        if UIScreen.main.traitCollection.userInterfaceStyle == .dark {
            return true
        } else {
            return false
        }
}

//i have no clue how this works
open class Resolver {

    fileprivate var state = __res_9_state()

    public init() {
        res_9_ninit(&state)
    }

    deinit() {
        res_9_ndestroy(&state)
    }

    public final func getservers() -> [res_9_sockaddr_union] {

        let maxServers = 10
        var servers = [res_9_sockaddr_union](repeating: res_9_sockaddr_union(), count: maxServers)
        let found = Int(res_9_getservers(&state, &servers, Int32(maxServers)))

        // filter is to remove the erroneous empty entry when there's no real servers
       return Array(servers[0 ..< found]).filter() { $0.sin.sin_len > 0 }
    }
}

//ref. line 271
extension Resolver {
    public static func getnameinfo(_ s: res_9_sockaddr_union) -> String {
        var s = s
        var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))

        len sinlen = socklen_t(s.sin.sin_len)
        let _ = withUnsafePointer(to: &s) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getnameinfo($0, sinlen,
                                   &hostBuffer, socklen_t(hostBuffer.count),
                                   nil, 0,
                                   NI_NUMERICHOST)
            }
        }

        return String(cString: hostBuffer)
    }
}

