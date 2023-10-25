var http_proxy = "PROXY 10.0.2.4:8444";
var https_proxy = "PROXY 10.0.2.4:8443";

function FindProxyForURL(url, host) {
  if (url.startsWith('https:')) {
    return https_proxy;
  } else {
  return http_proxy;
  }
}